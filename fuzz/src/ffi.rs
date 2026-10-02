//! The C API of both libraries, reached through the renamed symbols `build.rs` produces.

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

/// One library's entry points, so the harness drives either side through the same code.
pub(crate) struct Api {
    pub(crate) open_v2:
        unsafe extern "C" fn(*const c_char, *mut *mut Sqlite3, c_int, *const c_char) -> c_int,
    pub(crate) close_v2: unsafe extern "C" fn(*mut Sqlite3) -> c_int,
    pub(crate) key: unsafe extern "C" fn(*mut Sqlite3, *const c_void, c_int) -> c_int,
    pub(crate) prepare_v2: unsafe extern "C" fn(
        *mut Sqlite3,
        *const c_char,
        c_int,
        *mut *mut Stmt,
        *mut *const c_char,
    ) -> c_int,
    pub(crate) step: unsafe extern "C" fn(*mut Stmt) -> c_int,
    pub(crate) reset: unsafe extern "C" fn(*mut Stmt) -> c_int,
    pub(crate) clear_bindings: unsafe extern "C" fn(*mut Stmt) -> c_int,
    pub(crate) finalize: unsafe extern "C" fn(*mut Stmt) -> c_int,
    pub(crate) bind_null: unsafe extern "C" fn(*mut Stmt, c_int) -> c_int,
    pub(crate) bind_int64: unsafe extern "C" fn(*mut Stmt, c_int, i64) -> c_int,
    pub(crate) bind_double: unsafe extern "C" fn(*mut Stmt, c_int, c_double) -> c_int,
    pub(crate) bind_text:
        unsafe extern "C" fn(*mut Stmt, c_int, *const c_char, c_int, Destructor) -> c_int,
    pub(crate) bind_blob:
        unsafe extern "C" fn(*mut Stmt, c_int, *const c_void, c_int, Destructor) -> c_int,
    pub(crate) column_count: unsafe extern "C" fn(*mut Stmt) -> c_int,
    pub(crate) column_type: unsafe extern "C" fn(*mut Stmt, c_int) -> c_int,
    pub(crate) column_int64: unsafe extern "C" fn(*mut Stmt, c_int) -> i64,
    pub(crate) column_double: unsafe extern "C" fn(*mut Stmt, c_int) -> c_double,
    pub(crate) column_text: unsafe extern "C" fn(*mut Stmt, c_int) -> *const u8,
    pub(crate) column_blob: unsafe extern "C" fn(*mut Stmt, c_int) -> *const c_void,
    pub(crate) column_bytes: unsafe extern "C" fn(*mut Stmt, c_int) -> c_int,
    pub(crate) sqlite3mc: Option<Sqlite3mcApi>,
}

/// SQLite3MC's configuration entry points, which SQLCipher lacks.
pub(crate) struct Sqlite3mcApi {
    pub(crate) config: unsafe extern "C" fn(*mut Sqlite3, *const c_char, c_int) -> c_int,
    pub(crate) config_cipher:
        unsafe extern "C" fn(*mut Sqlite3, *const c_char, *const c_char, c_int) -> c_int,
    pub(crate) cipher_index: unsafe extern "C" fn(*const c_char) -> c_int,
}

macro_rules! bindings {
    ($module:ident, $prefix:literal, { $($name:ident($($arg:ty),*) $(-> $ret:ty)?;)* }) => {
        mod $module {
            use super::{c_char, c_double, c_int, c_void, Destructor, Sqlite3, Stmt};

            unsafe extern "C" {
                $(
                    #[link_name = concat!($prefix, stringify!($name))]
                    pub(super) fn $name($(_: $arg),*) $(-> $ret)?;
                )*
            }
        }
    };
}

macro_rules! common {
    ($module:ident, $prefix:literal $(, $extra:ident($($arg:ty),*) -> $ret:ty)*) => {
        bindings!($module, $prefix, {
            sqlite3_open_v2(*const c_char, *mut *mut Sqlite3, c_int, *const c_char) -> c_int;
            sqlite3_close_v2(*mut Sqlite3) -> c_int;
            sqlite3_key(*mut Sqlite3, *const c_void, c_int) -> c_int;
            sqlite3_prepare_v2(*mut Sqlite3, *const c_char, c_int, *mut *mut Stmt, *mut *const c_char) -> c_int;
            sqlite3_step(*mut Stmt) -> c_int;
            sqlite3_reset(*mut Stmt) -> c_int;
            sqlite3_clear_bindings(*mut Stmt) -> c_int;
            sqlite3_finalize(*mut Stmt) -> c_int;
            sqlite3_bind_null(*mut Stmt, c_int) -> c_int;
            sqlite3_bind_int64(*mut Stmt, c_int, i64) -> c_int;
            sqlite3_bind_double(*mut Stmt, c_int, c_double) -> c_int;
            sqlite3_bind_text(*mut Stmt, c_int, *const c_char, c_int, Destructor) -> c_int;
            sqlite3_bind_blob(*mut Stmt, c_int, *const c_void, c_int, Destructor) -> c_int;
            sqlite3_column_count(*mut Stmt) -> c_int;
            sqlite3_column_type(*mut Stmt, c_int) -> c_int;
            sqlite3_column_int64(*mut Stmt, c_int) -> i64;
            sqlite3_column_double(*mut Stmt, c_int) -> c_double;
            sqlite3_column_text(*mut Stmt, c_int) -> *const u8;
            sqlite3_column_blob(*mut Stmt, c_int) -> *const c_void;
            sqlite3_column_bytes(*mut Stmt, c_int) -> c_int;
            $($extra($($arg),*) -> $ret;)*
        });
    };
}

common!(
    mc,
    "mc_",
    sqlite3mc_config(*mut Sqlite3, *const c_char, c_int) -> c_int,
    sqlite3mc_config_cipher(*mut Sqlite3, *const c_char, *const c_char, c_int) -> c_int,
    sqlite3mc_cipher_index(*const c_char) -> c_int
);
common!(sc, "sc_");

macro_rules! api {
    ($module:ident, $sqlite3mc:expr) => {
        Api {
            open_v2: $module::sqlite3_open_v2,
            close_v2: $module::sqlite3_close_v2,
            key: $module::sqlite3_key,
            prepare_v2: $module::sqlite3_prepare_v2,
            step: $module::sqlite3_step,
            reset: $module::sqlite3_reset,
            clear_bindings: $module::sqlite3_clear_bindings,
            finalize: $module::sqlite3_finalize,
            bind_null: $module::sqlite3_bind_null,
            bind_int64: $module::sqlite3_bind_int64,
            bind_double: $module::sqlite3_bind_double,
            bind_text: $module::sqlite3_bind_text,
            bind_blob: $module::sqlite3_bind_blob,
            column_count: $module::sqlite3_column_count,
            column_type: $module::sqlite3_column_type,
            column_int64: $module::sqlite3_column_int64,
            column_double: $module::sqlite3_column_double,
            column_text: $module::sqlite3_column_text,
            column_blob: $module::sqlite3_column_blob,
            column_bytes: $module::sqlite3_column_bytes,
            sqlite3mc: $sqlite3mc,
        }
    };
}

/// SQLite3 Multiple Ciphers, from `sqlite3mc-src`.
pub(crate) static SQLITE3MC: Api = api!(
    mc,
    Some(Sqlite3mcApi {
        config: mc::sqlite3mc_config,
        config_cipher: mc::sqlite3mc_config_cipher,
        cipher_index: mc::sqlite3mc_cipher_index,
    })
);

/// SQLCipher with its libtomcrypt provider, from `sqlcipher-src`.
pub(crate) static SQLCIPHER: Api = api!(sc, None);
