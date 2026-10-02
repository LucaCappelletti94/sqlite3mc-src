//! Differential fuzzing of SQLite3MC's `sqlcipher` scheme against SQLCipher on the same SQLite.

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
pub use input::{Algorithm, Case, Cell, Column, Config, Flip, Key, Op, Side, Table};
pub use run::run;
