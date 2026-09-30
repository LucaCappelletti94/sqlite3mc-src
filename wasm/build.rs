//! Embeds the files the native interop binary wrote, since a browser has no filesystem to read them from.

use std::fmt::Write as _;
use std::path::Path;

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/interop");
    println!("cargo::rerun-if-changed={}", dir.display());
    // A missing file fails the test that wants it, never this build, so clippy runs without them.
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("native-")
        })
        .collect();
    files.sort();
    let mut table = String::from("pub const NATIVE_FILES: &[(&str, &[u8])] = &[\n");
    for path in files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        writeln!(
            table,
            "({name:?}, include_bytes!({:?})),",
            path.canonicalize().unwrap()
        )
        .unwrap();
    }
    table.push_str("];\n");
    let out = Path::new(&std::env::var_os("OUT_DIR").unwrap()).join("native_files.rs");
    std::fs::write(out, table).unwrap();
}
