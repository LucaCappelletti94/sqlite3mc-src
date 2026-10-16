//! Compiles the vendored amalgamation as a plain static library.

use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    assert_eq!(
        env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("linux"),
        "the fuzz crate builds on Linux only"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let mc_dir = sqlite3mc_src::source_dir();
    let mut cc = cc::Build::new();
    cc.file(mc_dir.join(sqlite3mc_src::SOURCE_FILE))
        .warnings(false);
    cc.include(mc_dir);
    for (name, value) in [
        ("SQLITE_CORE", None),
        ("SQLITE_TEMP_STORE", Some("2")),
        ("SQLITE_ENABLE_DBPAGE_VTAB", None),
        ("SQLITE_DEFAULT_MEMSTATUS", Some("0")),
    ] {
        cc.define(name, value);
    }
    instrument(&mut cc);
    let objects = cc.compile_intermediates();
    let [object] = objects.as_slice() else {
        panic!("the amalgamation compiled to {} objects", objects.len());
    };
    let archive = out.join("libmc.a");
    let _ = fs::remove_file(&archive);
    run(cc.get_archiver().arg("crs").arg(&archive).arg(object));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=mc");
    for lib in ["m", "pthread", "dl"] {
        println!("cargo:rustc-link-lib={lib}");
    }
    println!("cargo:rerun-if-changed=build.rs");
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

fn run(command: &mut Command) {
    let output = command
        .output()
        .unwrap_or_else(|e| panic!("cannot run {command:?}: {e}"));
    assert!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
