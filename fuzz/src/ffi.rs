//! The C API of the vendored amalgamation, its `sqlite3mc_*` extensions included.
//!
//! Every handle is an opaque foreign allocation owned by SQLite3MC, moved through
//! [`crate::db`] as a `NonNull` and released by exactly one matching call. Every `&CStr`
//! parameter is NUL-terminated and must outlive the call; the amalgamation copies what it keeps.

use core::ffi::{c_char, c_double, c_int, c_void};

/// Opaque `sqlite3` connection.
#[repr(C)]
pub(crate) struct Sqlite3 {
    _private: [u8; 0],
}

/// Opaque `sqlite3_stmt`.
#[repr(C)]
pub(crate) struct Stmt {
    _private: [u8; 0],
}

/// Opaque `sqlite3_backup`.
#[repr(C)]
pub(crate) struct Backup {
    _private: [u8; 0],
}

/// `SQLITE_STATIC`: the caller keeps bound bytes alive until the statement is reset.
pub(crate) type Destructor = Option<unsafe extern "C" fn(*mut c_void)>;

pub(crate) const SQLITE_OK: c_int = 0;
pub(crate) const SQLITE_ROW: c_int = 100;
pub(crate) const SQLITE_DONE: c_int = 101;
pub(crate) const SQLITE_OPEN_READONLY: c_int = 0x01;
pub(crate) const SQLITE_OPEN_READWRITE: c_int = 0x02;
pub(crate) const SQLITE_OPEN_CREATE: c_int = 0x04;
pub(crate) const SQLITE_INTEGER: c_int = 1;
pub(crate) const SQLITE_FLOAT: c_int = 2;
pub(crate) const SQLITE_TEXT: c_int = 3;
pub(crate) const SQLITE_BLOB: c_int = 4;

unsafe extern "C" {
    pub(crate) fn sqlite3_open_v2(
        dbfilename: *const c_char,
        db: *mut *mut Sqlite3,
        flags: c_int,
        vfs: *const c_char,
    ) -> c_int;
    pub(crate) fn sqlite3_close_v2(db: *mut Sqlite3) -> c_int;
    pub(crate) fn sqlite3_key(db: *mut Sqlite3, key: *const c_void, keylen: c_int) -> c_int;
    pub(crate) fn sqlite3_rekey(db: *mut Sqlite3, key: *const c_void, keylen: c_int) -> c_int;
    pub(crate) fn sqlite3_prepare_v2(
        db: *mut Sqlite3,
        zsql: *const c_char,
        nbyte: c_int,
        stmt: *mut *mut Stmt,
        tail: *mut *const c_char,
    ) -> c_int;
    pub(crate) fn sqlite3_step(stmt: *mut Stmt) -> c_int;
    pub(crate) fn sqlite3_reset(stmt: *mut Stmt) -> c_int;
    pub(crate) fn sqlite3_clear_bindings(stmt: *mut Stmt) -> c_int;
    pub(crate) fn sqlite3_finalize(stmt: *mut Stmt) -> c_int;
    pub(crate) fn sqlite3_bind_null(stmt: *mut Stmt, index: c_int) -> c_int;
    pub(crate) fn sqlite3_bind_int64(stmt: *mut Stmt, index: c_int, value: i64) -> c_int;
    pub(crate) fn sqlite3_bind_double(stmt: *mut Stmt, index: c_int, value: c_double) -> c_int;
    pub(crate) fn sqlite3_bind_text(
        stmt: *mut Stmt,
        index: c_int,
        value: *const c_char,
        nbyte: c_int,
        destructor: Destructor,
    ) -> c_int;
    pub(crate) fn sqlite3_bind_blob(
        stmt: *mut Stmt,
        index: c_int,
        value: *const c_void,
        nbyte: c_int,
        destructor: Destructor,
    ) -> c_int;
    pub(crate) fn sqlite3_column_count(stmt: *mut Stmt) -> c_int;
    pub(crate) fn sqlite3_column_type(stmt: *mut Stmt, i: c_int) -> c_int;
    pub(crate) fn sqlite3_column_int64(stmt: *mut Stmt, i: c_int) -> i64;
    pub(crate) fn sqlite3_column_double(stmt: *mut Stmt, i: c_int) -> c_double;
    pub(crate) fn sqlite3_column_text(stmt: *mut Stmt, i: c_int) -> *const u8;
    pub(crate) fn sqlite3_column_blob(stmt: *mut Stmt, i: c_int) -> *const c_void;
    pub(crate) fn sqlite3_column_bytes(stmt: *mut Stmt, i: c_int) -> c_int;
    pub(crate) fn sqlite3_backup_init(
        dest: *mut Sqlite3,
        destname: *const c_char,
        src: *mut Sqlite3,
        srcname: *const c_char,
    ) -> *mut Backup;
    pub(crate) fn sqlite3_backup_step(p: *mut Backup, n_page: c_int) -> c_int;
    pub(crate) fn sqlite3_backup_finish(p: *mut Backup) -> c_int;
    /// SQLite3MC's own entry points, absent from upstream SQLite.
    pub(crate) fn sqlite3mc_config(db: *mut Sqlite3, param: *const c_char, value: c_int) -> c_int;
    pub(crate) fn sqlite3mc_config_cipher(
        db: *mut Sqlite3,
        cipher: *const c_char,
        param: *const c_char,
        value: c_int,
    ) -> c_int;
    pub(crate) fn sqlite3mc_cipher_index(name: *const c_char) -> c_int;
}
