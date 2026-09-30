//! SQLite3MC as sqlite-wasm-rs builds it from this crate, and the checks its tests share.
//!
//! The files native SQLite3MC wrote come in through `build.rs`, and the files these tests write go back
//! as `sqlite3mc-interop-file` lines in the test output, since a browser has no filesystem.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sqlite_wasm_rs as ffi;
use sqlite_wasm_rs::vfs::memvfs::MemVfsUtil;
use sqlite_wasm_rs::vfs::transfer::DbTransfer;
use std::fmt::Debug;

#[path = "../../smoke/src/exchange.rs"]
pub mod exchange;

include!(concat!(env!("OUT_DIR"), "/native_files.rs"));

/// Initializes SQLite and returns the in-memory default VFS.
///
/// # Panics
///
/// If SQLite fails to initialize.
#[must_use]
pub fn memvfs() -> MemVfsUtil {
    // A Wasm instance runs one thread, so nothing else calls into SQLite meanwhile.
    assert_eq!(unsafe { ffi::sqlite3_initialize() }, ffi::SQLITE_OK);
    // The default VFS stays registered for the life of the instance.
    unsafe { MemVfsUtil::get() }.unwrap()
}

/// Imports every `native-<cipher>.db` into `vfs`, which backs the default VFS, and checks it.
///
/// # Panics
///
/// If a native file is missing or fails a check.
pub fn read_native_files<T: DbTransfer>(vfs: &T)
where
    T::Error: Debug,
{
    for (cipher, pragmas) in exchange::CIPHERS {
        let name = format!("native-{cipher}.db");
        let (_, bytes) = NATIVE_FILES
            .iter()
            .find(|(file, _)| *file == name)
            .unwrap_or_else(|| panic!("no {name} in target/interop, which interop.sh fills"));
        vfs.import_db_unchecked(&name, bytes).unwrap();
        exchange::check(&name, bytes, pragmas, exchange::NATIVE);
    }
}

/// Writes and checks `wasm-<cipher>.db` for every cipher through the default VFS, which `vfs` backs,
/// and returns a `sqlite3mc-interop-file <vfs_label>-<cipher> <base64> end` line for each.
///
/// # Panics
///
/// If a file leaks plaintext or does not read back.
pub fn write_every_cipher<T: DbTransfer>(vfs: &T, vfs_label: &str) -> Vec<String>
where
    T::Error: Debug,
{
    let mut lines = Vec::new();
    for (cipher, pragmas) in exchange::CIPHERS {
        let name = format!("wasm-{cipher}.db");
        exchange::write(&name, pragmas, exchange::WASM);
        let bytes = vfs.export_db(&name).unwrap();
        exchange::check(&name, &bytes, pragmas, exchange::WASM);
        let data = STANDARD.encode(bytes);
        lines.push(format!(
            "sqlite3mc-interop-file {vfs_label}-{cipher} {data} end"
        ));
    }
    lines
}
