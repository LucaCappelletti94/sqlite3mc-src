//! Compiles SQLite3MC and SQLCipher into one binary, prefixing each object's globals apart.

use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// One compiler invocation of a side, its objects merge before the rename.
struct Unit<'a> {
    files: &'a [PathBuf],
    includes: &'a [PathBuf],
    defines: &'a [(&'a str, Option<&'a str>)],
    forced_include: Option<&'a str>,
}

struct Side<'a> {
    prefix: &'a str,
    units: &'a [Unit<'a>],
}

fn main() {
    assert_eq!(
        env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("linux"),
        "the symbol renaming needs ELF objects and GNU-compatible nm and objcopy, so the fuzz crate builds on Linux only"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let crate_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let mc_dir = sqlite3mc_src::source_dir().to_path_buf();
    let sc_dir = sqlcipher_src::source_dir().to_path_buf();
    let ltc_dir = sc_dir.join(sqlcipher_src::LIBTOMCRYPT_INCLUDE_DIR);
    let common = [
        ("SQLITE_TEMP_STORE", Some("2")),
        ("SQLITE_ENABLE_DBPAGE_VTAB", None),
        ("SQLITE_DEFAULT_MEMSTATUS", Some("0")),
    ];
    let mc_defines: Vec<(&str, Option<&str>)> =
        [common.as_slice(), &[("SQLITE_CORE", None)]].concat();
    let ltc_files: Vec<PathBuf> = std::iter::once("sqlcipher-entropy.c")
        .map(|name| crate_dir.join(name))
        .chain(
            sqlcipher_src::LIBTOMCRYPT_SOURCES
                .iter()
                .map(|source| sc_dir.join(source)),
        )
        .collect();
    let mc_files = [mc_dir.join(sqlite3mc_src::SOURCE_FILE)];
    let mc_includes = [mc_dir];
    let wrapper_files = [crate_dir.join("sqlcipher-wrapper.c")];
    let wrapper_includes = [sc_dir, ltc_dir.clone()];
    let ltc_includes = [ltc_dir, crate_dir];
    build(
        &Side {
            prefix: "mc",
            units: &[Unit {
                files: &mc_files,
                includes: &mc_includes,
                defines: &mc_defines,
                forced_include: None,
            }],
        },
        &out,
    );
    build(
        &Side {
            prefix: "sc",
            units: &[
                Unit {
                    files: &wrapper_files,
                    includes: &wrapper_includes,
                    defines: &common,
                    forced_include: None,
                },
                Unit {
                    files: &ltc_files,
                    includes: &ltc_includes,
                    defines: &[("LTC_SOURCE", None)],
                    forced_include: Some("sqlcipher-ltc.h"),
                },
            ],
        },
        &out,
    );
    println!("cargo:rustc-link-search=native={}", out.display());
    for lib in ["m", "pthread", "dl"] {
        println!("cargo:rustc-link-lib={lib}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=sqlcipher-wrapper.c");
    println!("cargo:rerun-if-changed=sqlcipher-entropy.c");
    println!("cargo:rerun-if-changed=sqlcipher-ltc.h");
    println!("cargo:rerun-if-env-changed=NM");
    println!("cargo:rerun-if-env-changed=OBJCOPY");
    println!("cargo:rerun-if-env-changed=LD");
    println!("cargo:rerun-if-env-changed=AR");
}

fn build(side: &Side<'_>, out: &Path) {
    let mut objects = Vec::new();
    for unit in side.units {
        for file in unit.files {
            println!("cargo:rerun-if-changed={}", file.display());
        }
        let mut cc = cc::Build::new();
        for file in unit.files {
            cc.file(file);
        }
        for dir in unit.includes {
            cc.include(dir);
        }
        cc.warnings(false);
        for (name, value) in unit.defines {
            cc.define(name, *value);
        }
        if let Some(header) = unit.forced_include {
            cc.flag("-include").flag(header);
        }
        instrument(&mut cc);
        let unit_objects = cc.compile_intermediates();
        assert_eq!(
            unit_objects.len(),
            unit.files.len(),
            "{} compiled to {} objects",
            unit.files[0].display(),
            unit_objects.len()
        );
        objects.extend(unit_objects);
    }

    let combined = if objects.len() == 1 {
        objects.remove(0)
    } else {
        // Clang's .group sections break the final link once a partial link merges them.
        let linked: Vec<PathBuf> = objects
            .iter()
            .map(|object| strip_group_sections(object))
            .collect();
        let combined = out.join(format!("{}.combined.o", side.prefix));
        // The per-global asan sections survive a bfd partial link, while a gold one
        // drops most of them and ASan then never registers the side's globals.
        run(Command::new(tool("LD", "ld"))
            .arg("-r")
            .arg("-o")
            .arg(&combined)
            .args(&linked));
        combined
    };

    let map = out.join(format!("{}.redefine", side.prefix));
    fs::write(&map, redefinitions(&combined, side.prefix)).expect("OUT_DIR is writable");
    let renamed = out.join(format!("{}.o", side.prefix));
    run(Command::new(tool("OBJCOPY", "objcopy"))
        .arg(format!("--redefine-syms={}", map.display()))
        .arg(&combined)
        .arg(&renamed));

    let archive = out.join(format!("lib{}.a", side.prefix));
    let _ = fs::remove_file(&archive);
    run(Command::new(tool("AR", "ar"))
        .arg("crs")
        .arg(&archive)
        .arg(&renamed));
    println!("cargo:rustc-link-lib=static={}", side.prefix);
}

/// Gives the C side the coverage and sanitizer instrumentation `cargo fuzz` gives the Rust side.
fn instrument(cc: &mut cc::Build) {
    let fuzzing = env::var_os("CARGO_CFG_FUZZING").is_some();
    let sanitizers = env::var("CARGO_CFG_SANITIZE").unwrap_or_default();
    let address = sanitizers.split(',').any(|s| s == "address");
    if fuzzing || address {
        cc.compiler("clang");
    }
    if fuzzing {
        cc.flag("-fsanitize=fuzzer-no-link");
    }
    if address {
        cc.flag("-fsanitize=address");
    }
}

/// One `old new` line per global symbol the object defines.
fn redefinitions(object: &Path, prefix: &str) -> String {
    let listing = run(Command::new(tool("NM", "nm"))
        .args(["--defined-only", "--extern-only", "--format=posix"])
        .arg(object));
    listing
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .fold(String::new(), |mut map, name| {
            let _ = writeln!(map, "{name} {prefix}_{name}");
            map
        })
}

/// Returns a copy of `object` without its `.group` section.
fn strip_group_sections(object: &Path) -> PathBuf {
    let stem = object.file_stem().expect("object has a stem");
    let stripped = object.with_file_name(format!("{}.ng.o", stem.to_string_lossy()));
    run(Command::new(tool("OBJCOPY", "objcopy"))
        .arg("--remove-section=.group")
        .arg(object)
        .arg(&stripped));
    stripped
}

fn tool(var: &str, default: &str) -> String {
    env::var(var).unwrap_or_else(|_| default.to_owned())
}

fn run(command: &mut Command) -> String {
    let output = command
        .output()
        .unwrap_or_else(|e| panic!("cannot run {command:?}: {e}"));
    assert!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("tool output is UTF-8")
}
