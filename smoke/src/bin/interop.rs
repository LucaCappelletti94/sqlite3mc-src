//! `write DIR` creates `native-<cipher>.db` for every cipher, `read DIR PREFIX` checks the `PREFIX-<cipher>.db` Wasm wrote.

#[expect(
    unreachable_pub,
    reason = "The Wasm crate exports this shared module to its integration tests"
)]
#[path = "../exchange.rs"]
mod exchange;

#[expect(
    clippy::redundant_pub_crate,
    reason = "Restricted FFI visibility satisfies `unreachable_pub` in this binary"
)]
mod ffi {
    use std::ffi::{c_char, c_int, c_uchar, c_void};

    #[repr(C)]
    pub(super) struct sqlite3 {
        _private: [u8; 0],
    }

    #[repr(C)]
    pub(super) struct sqlite3_stmt {
        _private: [u8; 0],
    }

    pub(super) const SQLITE_OK: c_int = 0;
    pub(super) const SQLITE_NOTADB: c_int = 26;
    pub(super) const SQLITE_ROW: c_int = 100;
    pub(super) const SQLITE_OPEN_READWRITE: c_int = 2;
    pub(super) const SQLITE_OPEN_CREATE: c_int = 4;

    type ExecCallback =
        unsafe extern "C" fn(*mut c_void, c_int, *mut *mut c_char, *mut *mut c_char) -> c_int;

    unsafe extern "C" {
        pub(super) fn sqlite3_open_v2(
            filename: *const c_char,
            db: *mut *mut sqlite3,
            flags: c_int,
            vfs: *const c_char,
        ) -> c_int;
        pub(super) fn sqlite3_close(db: *mut sqlite3) -> c_int;
        pub(super) fn sqlite3_exec(
            db: *mut sqlite3,
            sql: *const c_char,
            callback: Option<ExecCallback>,
            arg: *mut c_void,
            errmsg: *mut *mut c_char,
        ) -> c_int;
        pub(super) fn sqlite3_prepare_v2(
            db: *mut sqlite3,
            sql: *const c_char,
            bytes: c_int,
            stmt: *mut *mut sqlite3_stmt,
            tail: *mut *const c_char,
        ) -> c_int;
        pub(super) fn sqlite3_step(stmt: *mut sqlite3_stmt) -> c_int;
        pub(super) fn sqlite3_column_text(stmt: *mut sqlite3_stmt, column: c_int)
            -> *const c_uchar;
        pub(super) fn sqlite3_finalize(stmt: *mut sqlite3_stmt) -> c_int;
        pub(super) fn sqlite3_errmsg(db: *mut sqlite3) -> *const c_char;
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (write, dir, prefix) = match args.as_slice() {
        [command, dir] if command == "write" => (true, dir, "native"),
        [command, dir, prefix] if command == "read" => (false, dir, prefix.as_str()),
        _ => panic!("usage: interop write DIR | interop read DIR PREFIX"),
    };
    let marker = if write {
        // Files of an earlier run must never pass for this one's.
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        exchange::NATIVE
    } else {
        exchange::WASM
    };
    for (cipher, pragmas) in exchange::CIPHERS {
        let name = format!("{dir}/{prefix}-{cipher}.db");
        if write {
            exchange::write(&name, pragmas, marker);
        }
        let bytes = std::fs::read(&name).unwrap_or_else(|e| panic!("{name}: {e}"));
        exchange::check(&name, &bytes, pragmas, marker);
    }
}
