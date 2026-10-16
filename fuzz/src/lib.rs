//! Fuzzing SQLite3MC's own cipher schemes for self-consistency, its rekey support, its WAL
//! journal mode, its `ATTACH DATABASE` support, its `sqlite3_backup_*` API, and its shared-cache
//! mode.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub wants pub(crate) on items the private modules share"
)]

mod db;
mod ffi;
mod input;
mod run;
pub mod seedgen;

pub use input::{
    Algorithm, AttachCase, BackupCase, Checkpoint, Cipher, NativeCase, NativeKey, Op, RekeyAction,
    RekeyCase, SharedCacheCase, SiblingKey, Table, WalCase,
};
pub use run::{run_attach, run_backup, run_native, run_rekey, run_shared_cache, run_wal};
