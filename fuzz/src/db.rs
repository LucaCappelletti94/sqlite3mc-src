//! Safe owners for connections and statements, keeping every raw handle inside this module.

use core::{
    ffi::{c_char, c_int, c_void, CStr},
    marker::PhantomData,
    ptr::{self, NonNull},
    slice,
};

use crate::ffi::{
    Api, Sqlite3, Stmt, SQLITE_BLOB, SQLITE_DONE, SQLITE_FLOAT, SQLITE_INTEGER, SQLITE_OK,
    SQLITE_ROW, SQLITE_TEXT,
};

/// An SQLite primary result code, the low byte of an extended one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Code(pub i32);

impl Code {
    const fn of(rc: c_int) -> Self {
        Self(rc & 0xff)
    }
}

const fn check(rc: c_int) -> Result<(), Code> {
    if rc == SQLITE_OK {
        Ok(())
    } else {
        Err(Code::of(rc))
    }
}

/// A column value as SQLite stored it, with floats compared bit for bit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `NULL`.
    Null,
    /// An integer.
    Integer(i64),
    /// The bits of a float.
    Real(u64),
    /// Text as raw bytes, which a damaged file need not keep UTF-8.
    Text(Vec<u8>),
    /// A blob.
    Blob(Vec<u8>),
}

/// A parameter bound for the duration of one [`Statement::run`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum Param<'a> {
    Null,
    Integer(i64),
    Real(f64),
    Text(&'a str),
    Blob(&'a [u8]),
}

/// `sqlite3_enable_shared_cache`: process-wide, not tied to any one connection. Every connection
/// opened after this call defaults to shared-cache mode (`SQLITE_OPEN_PRIVATECACHE` overrides it
/// per connection, not used anywhere in this harness).
pub(crate) fn enable_shared_cache(api: &Api, enable: bool) -> Result<(), Code> {
    // SAFETY: takes a plain `c_int`, touches no pointers, safe to call at any time.
    check(unsafe { (api.enable_shared_cache)(c_int::from(enable)) })
}

/// An open connection, closed on drop.
pub(crate) struct Connection<'a> {
    api: &'a Api,
    db: NonNull<Sqlite3>,
}

impl<'a> Connection<'a> {
    pub(crate) fn open(api: &'a Api, path: &CStr, flags: c_int) -> Result<Self, Code> {
        let mut db = ptr::null_mut();
        // SAFETY: `path` is NUL-terminated and outlives the call, the VFS name is NULL for the
        // default, and `db` is a valid place for SQLite to store the new handle or NULL.
        let rc = unsafe { (api.open_v2)(path.as_ptr(), &raw mut db, flags, ptr::null()) };
        let db = NonNull::new(db);
        match (rc, db) {
            (SQLITE_OK, Some(db)) => Ok(Self { api, db }),
            (_, db) => {
                if let Some(db) = db {
                    // SAFETY: a failed open still returns a handle SQLite requires closing, and
                    // nothing else holds it.
                    unsafe { (api.close_v2)(db.as_ptr()) };
                }
                // SQLITE_ERROR stands in for an OK code that came without a handle.
                Err(Code::of(if rc == SQLITE_OK { 1 } else { rc }))
            }
        }
    }

    pub(crate) fn key(&self, key: &[u8]) -> Result<(), Code> {
        let len = c_int::try_from(key.len()).expect("keys are short");
        // SAFETY: `self.db` is open, and `key` is valid for `len` bytes, which SQLite copies
        // before returning.
        check(unsafe { (self.api.key)(self.db.as_ptr(), key.as_ptr().cast(), len) })
    }

    /// Changes the key an already-open connection uses, empty bytes decrypting the database.
    pub(crate) fn rekey(&self, key: &[u8]) -> Result<(), Code> {
        let len = c_int::try_from(key.len()).expect("keys are short");
        // SAFETY: `self.db` is open, and `key` is valid for `len` bytes, which SQLite copies
        // before returning.
        check(unsafe { (self.api.rekey)(self.db.as_ptr(), key.as_ptr().cast(), len) })
    }

    const fn sqlite3mc(&self) -> &crate::ffi::Sqlite3mcApi {
        self.api
            .sqlite3mc
            .as_ref()
            .expect("only SQLite3MC has sqlite3mc_config")
    }

    /// Sets a connection-wide SQLite3MC parameter, returning the value now in effect or -1.
    pub(crate) fn sqlite3mc_config(&self, param: &CStr, value: c_int) -> c_int {
        let config = self.sqlite3mc().config;
        // SAFETY: `self.db` is open and `param` is NUL-terminated for the whole call.
        unsafe { config(self.db.as_ptr(), param.as_ptr(), value) }
    }

    /// Sets a cipher parameter, returning the value now in effect or -1.
    pub(crate) fn sqlite3mc_config_cipher(
        &self,
        cipher: &CStr,
        param: &CStr,
        value: c_int,
    ) -> c_int {
        let config_cipher = self.sqlite3mc().config_cipher;
        // SAFETY: `self.db` is open and both names are NUL-terminated for the whole call.
        unsafe { config_cipher(self.db.as_ptr(), cipher.as_ptr(), param.as_ptr(), value) }
    }

    /// The index `sqlite3mc_config` takes for the cipher named `name`.
    pub(crate) fn sqlite3mc_cipher_index(&self, name: &CStr) -> c_int {
        let cipher_index = self.sqlite3mc().cipher_index;
        // SAFETY: `name` is NUL-terminated for the whole call.
        unsafe { cipher_index(name.as_ptr()) }
    }

    pub(crate) fn prepare(&self, sql: &CStr) -> Result<Statement<'_>, Code> {
        let mut stmt = ptr::null_mut();
        // SAFETY: `self.db` is open, `sql` is NUL-terminated (length -1 reads up to the NUL),
        // `stmt` is a valid place for the handle, and the tail pointer is not requested.
        let rc = unsafe {
            (self.api.prepare_v2)(
                self.db.as_ptr(),
                sql.as_ptr(),
                -1,
                &raw mut stmt,
                ptr::null_mut(),
            )
        };
        check(rc)?;
        let stmt = NonNull::new(stmt).expect("the harness never prepares empty SQL");
        Ok(Statement {
            api: self.api,
            stmt,
            _connection: PhantomData,
        })
    }

    /// Runs one statement to completion, ignoring any rows it returns.
    pub(crate) fn execute(&self, sql: &CStr, params: &[Param<'_>]) -> Result<(), Code> {
        self.prepare(sql)?.run(params)
    }

    /// Starts a backup into `self` (as `dest_name`) from `src` (as `src_name`). `None` when the
    /// pair is refused outright, SQLite's own built-in restrictions or SQLite3MC's
    /// `sqlite3mcIsBackupSupported` compatibility guard alike.
    pub(crate) fn backup_init(
        &self,
        dest_name: &CStr,
        src: &Self,
        src_name: &CStr,
    ) -> Option<BackupJob<'a>> {
        // SAFETY: both connections are open for the call's duration, both names are
        // NUL-terminated, and the returned handle, if any, is owned by the new `BackupJob`.
        let handle = unsafe {
            (self.api.backup_init)(
                self.db.as_ptr(),
                dest_name.as_ptr(),
                src.db.as_ptr(),
                src_name.as_ptr(),
            )
        };
        NonNull::new(handle).map(|handle| BackupJob {
            api: self.api,
            handle,
        })
    }
}

/// A `sqlite3_backup` in progress. [`BackupJob::finish`] is the intended end; dropping one that
/// was never finished calls `sqlite3_backup_finish` anyway, so an early-abandoned backup is
/// still released.
pub(crate) struct BackupJob<'a> {
    api: &'a Api,
    handle: NonNull<crate::ffi::Backup>,
}

impl BackupJob<'_> {
    /// Runs up to `n_page` pages (negative for "all remaining"), returning the raw result code:
    /// callers need `SQLITE_DONE` (101) distinguished from a plain `SQLITE_OK` (0) success.
    pub(crate) fn step(&self, n_page: c_int) -> c_int {
        // SAFETY: the handle is valid until `finish`/drop, and `step` never invalidates it.
        unsafe { (self.api.backup_step)(self.handle.as_ptr(), n_page) }
    }

    /// Ends the backup. Finishes it immediately, then forgets `self` so [`BackupJob`]'s own
    /// `Drop` never runs and finishes the same handle a second time.
    pub(crate) fn finish(self) -> Result<(), Code> {
        // SAFETY: `handle` came from a successful `backup_init`; `mem::forget` below is what
        // keeps this the only call that finishes it.
        let result = check(unsafe { (self.api.backup_finish)(self.handle.as_ptr()) });
        core::mem::forget(self);
        result
    }
}

impl Drop for BackupJob<'_> {
    fn drop(&mut self) {
        // SAFETY: only reached when `finish` was never called, since `finish` forgets `self`
        // first; `self.handle` is still valid and this is its only release.
        unsafe {
            (self.api.backup_finish)(self.handle.as_ptr());
        }
    }
}

impl Drop for Connection<'_> {
    fn drop(&mut self) {
        // SAFETY: `self.db` came from a successful open and is closed only here. Statements
        // borrow the connection, so all of them were finalized before this runs.
        unsafe { (self.api.close_v2)(self.db.as_ptr()) };
    }
}

/// A prepared statement, finalized on drop and unable to outlive its connection.
pub(crate) struct Statement<'c> {
    api: &'c Api,
    stmt: NonNull<Stmt>,
    _connection: PhantomData<&'c Connection<'c>>,
}

impl Statement<'_> {
    /// Binds `params` and steps to the end, clearing the bindings before their borrows end.
    pub(crate) fn run(&mut self, params: &[Param<'_>]) -> Result<(), Code> {
        let result = self.bind(params).and_then(|()| loop {
            match self.step() {
                SQLITE_ROW => {}
                SQLITE_DONE => break Ok(()),
                rc => break Err(Code::of(rc)),
            }
        });
        // SAFETY: `self.stmt` is a live statement owned by `self`.
        unsafe { (self.api.reset)(self.stmt.as_ptr()) };
        // SAFETY: as above. After this SQLite holds no pointer into `params`.
        unsafe { (self.api.clear_bindings)(self.stmt.as_ptr()) };
        result
    }

    fn step(&mut self) -> c_int {
        // SAFETY: `self.stmt` is a live statement, and every bound buffer outlives the step,
        // since `run` clears bindings before its borrows end.
        unsafe { (self.api.step)(self.stmt.as_ptr()) }
    }

    fn bind(&mut self, params: &[Param<'_>]) -> Result<(), Code> {
        let stmt = self.stmt.as_ptr();
        for (index, param) in (1..).zip(params) {
            let rc = match *param {
                // SAFETY: `stmt` is live and `index` counts from 1 as SQLite expects.
                Param::Null => unsafe { (self.api.bind_null)(stmt, index) },
                // SAFETY: as above.
                Param::Integer(v) => unsafe { (self.api.bind_int64)(stmt, index, v) },
                // SAFETY: as above.
                Param::Real(v) => unsafe { (self.api.bind_double)(stmt, index, v) },
                Param::Text(v) => {
                    let len = c_int::try_from(v.len()).expect("text fits an int");
                    // SAFETY: `v` is valid for `len` bytes, and SQLITE_STATIC (the `None`
                    // destructor) is sound because `run` clears the binding before `v`'s
                    // borrow ends.
                    unsafe {
                        (self.api.bind_text)(stmt, index, v.as_ptr().cast::<c_char>(), len, None)
                    }
                }
                Param::Blob(v) => {
                    let len = c_int::try_from(v.len()).expect("blob fits an int");
                    // SAFETY: as for text.
                    unsafe {
                        (self.api.bind_blob)(stmt, index, v.as_ptr().cast::<c_void>(), len, None)
                    }
                }
            };
            check(rc)?;
        }
        Ok(())
    }

    /// The next row, `None` once the statement is done.
    pub(crate) fn next_row(&mut self) -> Result<Option<Vec<Value>>, Code> {
        match self.step() {
            SQLITE_ROW => {}
            SQLITE_DONE => return Ok(None),
            rc => return Err(Code::of(rc)),
        }
        // SAFETY: the statement is live and positioned on a row.
        let columns = unsafe { (self.api.column_count)(self.stmt.as_ptr()) };
        Ok(Some((0..columns).map(|i| self.column(i)).collect()))
    }

    /// Column `i` of the current row, where `i` is below the column count.
    fn column(&self, i: c_int) -> Value {
        let stmt = self.stmt.as_ptr();
        // SAFETY: the statement is positioned on a row and `i` is in range, which holds for
        // every accessor below.
        match unsafe { (self.api.column_type)(stmt, i) } {
            // SAFETY: as above.
            SQLITE_INTEGER => Value::Integer(unsafe { (self.api.column_int64)(stmt, i) }),
            // SAFETY: as above.
            SQLITE_FLOAT => Value::Real(unsafe { (self.api.column_double)(stmt, i) }.to_bits()),
            SQLITE_TEXT => {
                // SAFETY: as above. The pointer is fetched before its length, the order SQLite
                // documents for a stable result.
                let text = unsafe { (self.api.column_text)(stmt, i) };
                Value::Text(self.copy(text, i))
            }
            SQLITE_BLOB => {
                // SAFETY: as for text.
                let blob = unsafe { (self.api.column_blob)(stmt, i) }.cast::<u8>();
                Value::Blob(self.copy(blob, i))
            }
            _ => Value::Null,
        }
    }

    /// Copies the bytes `data` points at for column `i`, just fetched from the current row.
    fn copy(&self, data: *const u8, i: c_int) -> Vec<u8> {
        // SAFETY: the statement is on a row and `i` is in range, and asking for the length
        // after the pointer leaves the pointer valid.
        let len = unsafe { (self.api.column_bytes)(self.stmt.as_ptr(), i) };
        let len = usize::try_from(len).expect("SQLite reports non-negative lengths");
        if data.is_null() || len == 0 {
            return Vec::new();
        }
        // SAFETY: SQLite guarantees `data` addresses `len` initialized bytes until the next
        // step, reset or finalize, and none happens before the copy completes.
        unsafe { slice::from_raw_parts(data, len) }.to_vec()
    }
}

impl Drop for Statement<'_> {
    fn drop(&mut self) {
        // SAFETY: `self.stmt` came from a successful prepare and is finalized only here.
        unsafe { (self.api.finalize)(self.stmt.as_ptr()) };
    }
}
