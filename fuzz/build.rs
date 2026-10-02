//! Compiles SQLite3MC and SQLCipher into one binary, prefixing each object's globals apart.

use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

struct Side<'a> {
    prefix: &'a str,
    source: PathBuf,
    include: &'a Path,
    defines: &'a [(&'a str, Option<&'a str>)],
}

fn main() {
    assert_eq!(
        env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("linux"),
        "the symbol renaming needs ELF objects and GNU-compatible nm and objcopy, so the fuzz crate builds on Linux only"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let mc_dir = sqlite3mc_src::source_dir();
    let sc_dir = sqlcipher_src::source_dir();
    let common = [
        ("SQLITE_TEMP_STORE", Some("2")),
        ("SQLITE_ENABLE_DBPAGE_VTAB", None),
        ("SQLITE_DEFAULT_MEMSTATUS", Some("0")),
    ];
    let mc_defines = [common.as_slice(), &[("SQLITE_CORE", None)]].concat();
    build(
        &Side {
            prefix: "mc",
            source: mc_dir.join(sqlite3mc_src::SOURCE_FILE),
            include: mc_dir,
            defines: &mc_defines,
        },
        &out,
    );
    build(
        &Side {
            prefix: "sc",
            source: sc_dir.join(sqlcipher_src::WASM_SOURCE_FILE),
            include: sc_dir,
            defines: &common,
        },
        &out,
    );
    println!("cargo:rustc-link-search=native={}", out.display());
    for lib in ["m", "pthread", "dl"] {
        println!("cargo:rustc-link-lib={lib}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=NM");
    println!("cargo:rerun-if-env-changed=OBJCOPY");
}

fn build(side: &Side<'_>, out: &Path) {
    println!("cargo:rerun-if-changed={}", side.include.display());
    let mut cc = cc::Build::new();
    cc.file(&side.source).include(side.include).warnings(false);
    for (name, value) in side.defines {
        cc.define(name, *value);
    }
    instrument(&mut cc);
    let objects = cc.compile_intermediates();
    let [object] = objects.as_slice() else {
        panic!(
            "{} compiled to {} objects",
            side.source.display(),
            objects.len()
        );
    };

    let map = out.join(format!("{}.redefine", side.prefix));
    fs::write(&map, redefinitions(object, side.prefix)).expect("OUT_DIR is writable");
    let renamed = out.join(format!("{}.o", side.prefix));
    run(Command::new(tool("OBJCOPY", "objcopy"))
        .arg(format!("--redefine-syms={}", map.display()))
        .arg(object)
        .arg(&renamed));

    let archive = out.join(format!("lib{}.a", side.prefix));
    let _ = fs::remove_file(&archive);
    run(cc.get_archiver().arg("crs").arg(&archive).arg(&renamed));
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
