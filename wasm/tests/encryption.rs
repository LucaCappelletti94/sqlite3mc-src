//! SQLite3MC built by sqlite-wasm-rs from this crate is the vendored release, reads every native file,
//! and writes one per cipher for native to read.
use sqlite3mc_src_wasm::exchange::Db;
use sqlite3mc_src_wasm::{memvfs, read_native_files, write_every_cipher};
use wasm_bindgen_test::{console_log, wasm_bindgen_test};

#[wasm_bindgen_test]
fn compiles_the_vendored_release() {
    let _vfs = memvfs();
    let version = Db::open("version.db", &[]).text("SELECT sqlite3mc_version()");
    assert!(
        version.ends_with(sqlite3mc_src::SQLITE3MC_VERSION),
        "{version}"
    );
}

#[wasm_bindgen_test]
fn reads_every_native_file() {
    read_native_files(&memvfs());
}

#[wasm_bindgen_test]
fn writes_every_cipher_for_native() {
    for line in write_every_cipher(&memvfs(), "memvfs") {
        console_log!("{line}");
    }
}
