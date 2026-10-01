//! The encrypted files native and Wasm SQLite3MC hand each other, and the checks both sides run on them.
//! The native `interop` binary and the Wasm tests include this file, each next to its own `ffi` module.

use super::ffi;
use std::ffi::{c_int, CStr, CString};

const KEY: &str = "PRAGMA key = 'correct horse battery staple'";
const WRONG_KEY: &str = "PRAGMA key = 'wrong horse battery staple'";
/// Start of every row the native build writes.
pub const NATIVE: &str = "written natively";
/// Start of every row the Wasm build writes.
pub const WASM: &str = "written by Wasm";
/// Enough rows of about 100 bytes to fill several pages.
const ROWS: u32 = 400;
const SQLCIPHER: &str = "PRAGMA cipher = 'sqlcipher'";

/// Every cipher SQLite3MC ships, by file name, as the pragmas that select it before `PRAGMA key`.
/// A reader that skips the last pragma of a cipher must fail, which proves the pragmas took effect.
pub const CIPHERS: &[(&str, &[&str])] = &[
    ("chacha20", &[]),
    ("aes128cbc", &["PRAGMA cipher = 'aes128cbc'"]),
    ("aes256cbc", &["PRAGMA cipher = 'aes256cbc'"]),
    ("sqlcipher1", &[SQLCIPHER, "PRAGMA legacy = 1"]),
    ("sqlcipher2", &[SQLCIPHER, "PRAGMA legacy = 2"]),
    ("sqlcipher3", &[SQLCIPHER, "PRAGMA legacy = 3"]),
    ("sqlcipher4", &[SQLCIPHER, "PRAGMA legacy = 4"]),
    ("rc4", &["PRAGMA cipher = 'rc4'"]),
    ("ascon128", &["PRAGMA cipher = 'ascon128'"]),
    ("aegis", &["PRAGMA cipher = 'aegis'"]),
];

/// A connection to `name` in the side's default VFS, which fails the test on any SQLite error.
pub struct Db(*mut ffi::sqlite3, String);

impl Db {
    /// Opens `name` read-write, creating it if missing, and runs `pragmas`.
    ///
    /// # Panics
    ///
    /// If opening or a pragma fails.
    #[must_use]
    pub fn open(name: &str, pragmas: &[&str]) -> Self {
        let c_name = CString::new(name).unwrap();
        let mut handle = std::ptr::null_mut();
        let flags = ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE;
        // SAFETY: `c_name` is live and NUL-terminated, and `handle` is writable for the call.
        let rc = unsafe {
            ffi::sqlite3_open_v2(
                c_name.as_ptr(),
                std::ptr::addr_of_mut!(handle),
                flags,
                std::ptr::null(),
            )
        };
        let db = Self(handle, name.to_owned());
        assert_eq!(rc, ffi::SQLITE_OK, "{name}: {}", db.error());
        for pragma in pragmas {
            db.exec(pragma);
        }
        db
    }

    /// Runs `sql` and returns SQLite's result code.
    fn status(&self, sql: &str) -> c_int {
        let sql = CString::new(sql).unwrap();
        // `sql` outlives the call, and no callback or error pointer is passed.
        unsafe {
            let (arg, errmsg) = (std::ptr::null_mut(), std::ptr::null_mut());
            ffi::sqlite3_exec(self.0, sql.as_ptr(), None, arg, errmsg)
        }
    }

    fn exec(&self, sql: &str) {
        let rc = self.status(sql);
        assert_eq!(rc, ffi::SQLITE_OK, "{}: {sql}: {}", self.1, self.error());
    }

    /// First column of the first row of `sql`, as text.
    ///
    /// # Panics
    ///
    /// If it fails or returns no text.
    #[must_use]
    pub fn text(&self, sql: &str) -> String {
        let c_sql = CString::new(sql).unwrap();
        let mut stmt = std::ptr::null_mut();
        // SAFETY: The connection is live, `c_sql` is NUL-terminated, and `stmt` is writable for the call.
        let rc = unsafe {
            ffi::sqlite3_prepare_v2(
                self.0,
                c_sql.as_ptr(),
                -1,
                std::ptr::addr_of_mut!(stmt),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, ffi::SQLITE_OK, "{}: {sql}: {}", self.1, self.error());
        // `stmt` was just prepared, and the text is copied before it is finalized.
        let text = unsafe {
            let value = if ffi::sqlite3_step(stmt) == ffi::SQLITE_ROW {
                ffi::sqlite3_column_text(stmt, 0)
            } else {
                std::ptr::null()
            };
            let text = (!value.is_null())
                .then(|| CStr::from_ptr(value.cast()).to_string_lossy().into_owned());
            let error = self.error();
            ffi::sqlite3_finalize(stmt);
            text.ok_or(error)
        };
        text.unwrap_or_else(|error| panic!("{}: {sql}: {error}", self.1))
    }

    fn error(&self) -> String {
        // SQLite returns a NUL-terminated message for any handle, even a null one.
        unsafe { CStr::from_ptr(ffi::sqlite3_errmsg(self.0)) }
            .to_string_lossy()
            .into_owned()
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        // The handle came from `sqlite3_open_v2`, and every statement on it is finalized.
        unsafe { ffi::sqlite3_close(self.0) };
    }
}

/// Writes `name` in the format `pragmas` select, with rows starting with `marker`.
pub fn write(name: &str, pragmas: &[&str], marker: &str) {
    Db::open(name, &[pragmas, &[KEY]].concat()).exec(&format!(
        "CREATE TABLE t(v TEXT);
         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < {ROWS})
         INSERT INTO t SELECT '{marker} ' || i || ' ' || hex(zeroblob(40)) FROM n;"
    ));
}

/// Asserts `bytes`, the file `name` holding rows that start with `marker`, is encrypted on every page,
/// and that it opens with its key and pragmas, but not with a wrong key or without its last pragma.
///
/// # Panics
///
/// If any of that does not hold.
pub fn check(name: &str, bytes: &[u8], pragmas: &[&str], marker: &str) {
    assert!(bytes.len() > 16 * 1024, "{name} is {} bytes", bytes.len());
    for plain in [
        b"SQLite format 3".as_slice(),
        b"CREATE TABLE",
        marker.as_bytes(),
    ] {
        let leak = bytes.windows(plain.len()).any(|w| w == plain);
        assert!(!leak, "{name} holds {:?}", String::from_utf8_lossy(plain));
    }
    let db = Db::open(name, &[pragmas, &[KEY]].concat());
    assert_eq!(db.text("PRAGMA quick_check"), "ok", "{name}");
    let count = db.text(&format!("SELECT count(*) FROM t WHERE v LIKE '{marker} %'"));
    assert_eq!(count, ROWS.to_string(), "{name}");
    let probe = "SELECT count(*) FROM sqlite_schema";
    let rc = Db::open(name, &[pragmas, &[WRONG_KEY]].concat()).status(probe);
    assert_eq!(rc, ffi::SQLITE_NOTADB, "{name} opened with a wrong key");
    if let Some((_, fewer)) = pragmas.split_last() {
        let rc = Db::open(name, &[fewer, &[KEY]].concat()).status(probe);
        assert_eq!(
            rc,
            ffi::SQLITE_NOTADB,
            "{name} opened without its last pragma"
        );
    }
}
