//! Fuzzing SQLite3MC against SQLCipher differentially, its own native ciphers for
//! self-consistency, its rekey support, its WAL journal mode, its `ATTACH DATABASE` support, its
//! `sqlite3_backup_*` API, and its shared-cache mode, on the same SQLite.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub wants pub(crate) on items the private modules share"
)]

mod db;
mod entropy;
mod ffi;
mod input;
mod run;
pub mod seedgen;
/// The `ASan` default `detect_odr_violation` level (2 since clang 18) reports the two
/// renamed copies of the SQLite amalgamation as a violation, so the harness turns the
/// check off. `ASan` reads its default options from the weak symbol of this name, a
/// function returning the options string.
#[no_mangle]
const extern "C" fn __asan_default_options() -> *const u8 {
    c"detect_odr_violation=0".as_ptr().cast::<u8>()
}

pub use input::{
    Algorithm, AttachCase, BackupCase, Case, Checkpoint, Cipher, Config, Key, NativeCase,
    NativeKey, Op, RekeyAction, RekeyCase, SharedCacheCase, Side, Table, WalCase,
};
pub use run::{run, run_attach, run_backup, run_native, run_rekey, run_shared_cache, run_wal};
