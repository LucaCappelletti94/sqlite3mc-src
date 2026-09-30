//! The native exchange on the persistent OPFS `sahpool` VFS, which exists only in a browser's dedicated worker.
use sqlite3mc_src_wasm::exchange::CIPHERS;
use sqlite3mc_src_wasm::{read_native_files, write_every_cipher};
use sqlite_wasm_rs::{self as ffi, WasmOsCallback};
use sqlite_wasm_vfs::sahpool::{install, OpfsSAHPoolCfgBuilder};
use wasm_bindgen_test::{console_log, wasm_bindgen_test};

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
#[expect(
    clippy::future_not_send,
    reason = "the pool holds an Rc, and a Wasm worker has one thread"
)]
async fn exchanges_every_cipher_on_opfs() {
    let cfg = OpfsSAHPoolCfgBuilder::new()
        .vfs_name("sahpool")
        .directory("sqlite3mc-src")
        .clear_on_init(true)
        // Room for the files of both sides, each with its rollback journal.
        .initial_capacity(4 * CIPHERS.len())
        .build();
    let pool = install::<WasmOsCallback>(&cfg, false).await.unwrap();
    // SQLite3MC encrypts only through its own VFS wrapped around the real one, made the default here.
    let rc = unsafe { ffi::sqlite3mc_vfs_create(c"sahpool".as_ptr(), 1) };
    assert_eq!(rc, ffi::SQLITE_OK);
    read_native_files(&pool);
    for line in write_every_cipher(&pool, "opfs") {
        console_log!("{line}");
    }
}
