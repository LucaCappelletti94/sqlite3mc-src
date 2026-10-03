//! Fuzzing SQLite3MC against SQLCipher differentially, its own native ciphers for
//! self-consistency, its rekey support, and its WAL journal mode, on the same SQLite.

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
    Algorithm, Case, Cell, Checkpoint, Cipher, Column, Config, Flip, Key, NativeCase, NativeConfig,
    NativeKey, Op, RekeyAction, RekeyCase, Side, Table, WalCase, MAX_FLIPS, MAX_OPS,
};
pub use run::{run, run_native, run_rekey, run_wal};
