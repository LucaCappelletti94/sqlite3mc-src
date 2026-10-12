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

pub use input::{
    Algorithm, AttachCase, BackupCase, Case, Checkpoint, Cipher, Config, Key, NativeCase,
    NativeKey, Op, RekeyAction, RekeyCase, SharedCacheCase, SiblingKey, Side, Table, WalCase,
};
pub use run::{run, run_attach, run_backup, run_native, run_rekey, run_shared_cache, run_wal};
