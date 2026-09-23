#![doc = include_str!("../README.md")]

use std::path::Path;

/// SQLite3 Multiple Ciphers release the vendored amalgamation comes from.
pub const SQLITE3MC_VERSION: &str = "2.5.1";

/// SQLite release that amalgamation wraps.
pub const SQLITE_VERSION: &str = "3.53.4";

/// Amalgamation source inside [`source_dir`], under its upstream name.
pub const SOURCE_FILE: &str = "sqlite3mc_amalgamation.c";

/// Amalgamation header inside [`source_dir`], under its upstream name.
pub const HEADER_FILE: &str = "sqlite3mc_amalgamation.h";

/// SQLite's extension header from the same release, inside [`source_dir`].
pub const EXTENSION_HEADER_FILE: &str = "sqlite3ext.h";

/// Directory holding the release files byte for byte, for a consumer's build script to compile.
#[must_use]
pub fn source_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/sqlite3mc"))
}
