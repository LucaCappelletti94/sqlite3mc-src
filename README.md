# sqlite3mc-src

[![CI](https://github.com/LucaCappelletti94/sqlite3mc-src/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/sqlite3mc-src/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sqlite3mc-src.svg)](https://crates.io/crates/sqlite3mc-src)
[![docs.rs](https://docs.rs/sqlite3mc-src/badge.svg)](https://docs.rs/sqlite3mc-src)
[![license](https://img.shields.io/crates/l/sqlite3mc-src.svg)](LICENSE)

The [SQLite3 Multiple Ciphers](https://github.com/utelle/SQLite3MultipleCiphers) amalgamation, byte for byte as released, for `-sys` crates to compile with their own options. It compiles nothing and sets no defines, so every consumer keeps its own flags while one `Cargo.lock` gives them all the same source.

```rust
let source = sqlite3mc_src::source_dir().join(sqlite3mc_src::SOURCE_FILE);
assert!(source.is_file());
assert_eq!(sqlite3mc_src::SQLITE3MC_VERSION, "2.5.1");
```

The version encodes the SQLite3MC release, so `205.1.x` carries SQLite3MC 2.5.1 and a consumer requiring `205.1` receives SQLite3MC 2.5 patch releases only. SQLite3MC is MIT licensed, and the amalgamation also contains public-domain code (SQLite among it) and Argon2 under CC0-1.0 or Apache-2.0.

The files are refreshed with `upgrade.sh` in the [repository](https://github.com/LucaCappelletti94/sqlite3mc-src), which checks the release archive's SHA-256 before extracting them, and CI re-runs it to prove the vendored bytes match the release.
