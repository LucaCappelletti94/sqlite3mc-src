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

pub use db::{Code, Value};
pub use input::{
    Algorithm, AttachCase, AttachedDb, BackupCase, Case, Cell, Checkpoint, Cipher, Column, Config,
    Flip, Key, NativeCase, NativeConfig, NativeKey, Op, PageSize, RekeyAction, RekeyCase,
    SharedCacheCase, SharedConnection, Side, Table, WalCase, MAX_ATTACHED, MAX_ATTACH_ROWS,
    MAX_FLIPS, MAX_OPS, MAX_SIBLINGS,
};
pub use run::{run, run_attach, run_backup, run_native, run_rekey, run_shared_cache, run_wal};
