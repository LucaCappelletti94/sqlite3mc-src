//! Fuzzing SQLite3MC's own cipher schemes for self-consistency, its rekey support, its WAL
//! journal mode, its `ATTACH DATABASE` support, and its `sqlite3_backup_*` API.

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
    RekeyCase, Table, WalCase,
};
pub use run::{run_attach, run_backup, run_native, run_rekey, run_wal};
