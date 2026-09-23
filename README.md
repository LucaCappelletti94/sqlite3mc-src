# sqlite3mc-src

[![CI](https://github.com/LucaCappelletti94/sqlite3mc-src/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/sqlite3mc-src/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/LucaCappelletti94/sqlite3mc-src/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/sqlite3mc-src)
[![Quality gate](https://sonarcloud.io/api/project_badges/measure?project=LucaCappelletti94_sqlite3mc-src&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=LucaCappelletti94_sqlite3mc-src)
[![crates.io](https://img.shields.io/crates/v/sqlite3mc-src.svg)](https://crates.io/crates/sqlite3mc-src)
[![docs.rs](https://docs.rs/sqlite3mc-src/badge.svg)](https://docs.rs/sqlite3mc-src)
[![license](https://img.shields.io/crates/l/sqlite3mc-src.svg)](https://github.com/LucaCappelletti94/sqlite3mc-src/blob/main/LICENSE)

The [SQLite3 Multiple Ciphers](https://github.com/utelle/SQLite3MultipleCiphers) amalgamation, byte for byte as released, for `-sys` crates to compile with their own options. It compiles nothing and sets no defines, so every consumer keeps its own flags while one `Cargo.lock` gives them all the same source.

```rust
let dir = sqlite3mc_src::source_dir();
assert!(dir.join(sqlite3mc_src::SOURCE_FILE).is_file());
assert!(dir.join(sqlite3mc_src::HEADER_FILE).is_file());
```

The version encodes the release, so `205.1.x` is SQLite3MC 2.5.1. A `205.1` requirement also accepts later 2.5 patch releases, never 2.6. Those may wrap a newer SQLite, named by `SQLITE_VERSION`, so a `-sys` crate with committed bindings regenerates them.

SQLite3MC is MIT licensed, and the amalgamation also carries public-domain code and Argon2 under CC0-1.0 or Apache-2.0.

A daily workflow in the [repository](https://github.com/LucaCappelletti94/sqlite3mc-src) opens a pull request for each new SQLite3MC release, taking the archive's checksum only from the release's Sigstore-signed `SHA256SUMS`. CI re-runs `upgrade.sh` to prove the vendored bytes match the pinned release.
