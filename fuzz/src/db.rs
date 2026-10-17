//! Safe owners for connections and statements, keeping every raw handle inside this module.
//! Each handle is released by exactly one matching amalgamation call, in its own `Drop`.

use core::{
    ffi::{c_char, c_int, c_void, CStr},
    marker::PhantomData,
    ptr::{self, NonNull},
    slice,
};

use crate::ffi;

/// An SQLite primary result code, the low byte of an extended one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Code(pub(crate) i32);

impl Code {
    const fn of(rc: c_int) -> Self {
        Self(rc & 0xff)
    }
}

const fn check(rc: c_int) -> Result<(), Code> {
    if rc == ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(Code::of(rc))
    }
}

/// A column value as SQLite stored it, with floats compared bit for bit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
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

/// An open connection, closed on drop.
pub(crate) struct Connection {
    db: NonNull<ffi::Sqlite3>,
}

impl Connection {
    pub(crate) fn open(path: &CStr, flags: c_int) -> Result<Self, Code> {
        let mut db = ptr::null_mut();
        // SAFETY: `path` is NUL-terminated and outlives the call, the VFS name is NULL for
        // the default, and `db` is a valid place for SQLite to store the new handle or NULL.
        let rc = unsafe { ffi::sqlite3_open_v2(path.as_ptr(), &raw mut db, flags, ptr::null()) };
        let db = NonNull::new(db);
        match (rc, db) {
            (ffi::SQLITE_OK, Some(db)) => Ok(Self { db }),
            (_, db) => {
                if let Some(db) = db {
                    // SAFETY: a failed open still returns a handle SQLite requires closing, and
                    // nothing else holds it.
                    unsafe { ffi::sqlite3_close_v2(db.as_ptr()) };
                }
                // SQLITE_ERROR stands in for an OK code that came without a handle.
                Err(Code::of(if rc == ffi::SQLITE_OK { 1 } else { rc }))
            }
        }
    }

    pub(crate) fn key(&self, key: &[u8]) -> Result<(), Code> {
        let len = c_int::try_from(key.len()).expect("keys are short");
        // SAFETY: `self.db` is open, and `key` is valid for `len` bytes, which SQLite copies
        // before returning.
        check(unsafe { ffi::sqlite3_key(self.db.as_ptr(), key.as_ptr().cast(), len) })
    }

    /// Changes the key an already-open connection uses, empty bytes decrypting the database.
    pub(crate) fn rekey(&self, key: &[u8]) -> Result<(), Code> {
        let len = c_int::try_from(key.len()).expect("keys are short");
        // SAFETY: `self.db` is open, and `key` is valid for `len` bytes, which SQLite copies
        // before returning.
        check(unsafe { ffi::sqlite3_rekey(self.db.as_ptr(), key.as_ptr().cast(), len) })
    }

    /// Sets a connection-wide SQLite3MC parameter, returning the value now in effect or -1.
    pub(crate) fn sqlite3mc_config(&self, param: &CStr, value: c_int) -> c_int {
        // SAFETY: `self.db` is open and `param` is NUL-terminated for the whole call.
        unsafe { ffi::sqlite3mc_config(self.db.as_ptr(), param.as_ptr(), value) }
    }

    /// Sets a cipher parameter, returning the value now in effect or -1.
    pub(crate) fn sqlite3mc_config_cipher(
        &self,
        cipher: &CStr,
        param: &CStr,
        value: c_int,
    ) -> c_int {
        // SAFETY: `self.db` is open and both names are NUL-terminated for the whole call.
        unsafe {
            ffi::sqlite3mc_config_cipher(self.db.as_ptr(), cipher.as_ptr(), param.as_ptr(), value)
        }
    }

    /// The index `sqlite3mc_config` takes for the cipher named `name`.
    pub(crate) fn sqlite3mc_cipher_index(name: &CStr) -> c_int {
        // SAFETY: `name` is NUL-terminated for the whole call.
        unsafe { ffi::sqlite3mc_cipher_index(name.as_ptr()) }
    }

    pub(crate) fn prepare(&self, sql: &CStr) -> Result<Statement<'_>, Code> {
        let mut stmt = ptr::null_mut();
        // SAFETY: `self.db` is open, `sql` is NUL-terminated (length -1 reads up to the NUL),
        // `stmt` is a valid place for the handle, and the tail pointer is not requested.
        let rc = unsafe {
            ffi::sqlite3_prepare_v2(
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
            stmt,
            _connection: PhantomData,
        })
    }

    /// Runs one statement to completion, ignoring any rows it returns.
    pub(crate) fn execute(&self, sql: &CStr, params: &[Param<'_>]) -> Result<(), Code> {
        self.prepare(sql)?.run(params)
    }

    /// Starts a backup into `self` from `src`, `None` when SQLite's own restrictions or
    /// SQLite3MC's compatibility guard refuse the pair.
    pub(crate) fn backup_init(
        &self,
        dest_name: &CStr,
        src: &Self,
        src_name: &CStr,
    ) -> Option<BackupJob> {
        // SAFETY: both connections are open for the call's duration, both names are
        // NUL-terminated, and the returned handle, if any, is owned by the new `BackupJob`.
        let handle = unsafe {
            ffi::sqlite3_backup_init(
                self.db.as_ptr(),
                dest_name.as_ptr(),
                src.db.as_ptr(),
                src_name.as_ptr(),
            )
        };
        NonNull::new(handle).map(|handle| BackupJob { handle })
    }
}

/// A `sqlite3_backup` in progress; dropping one never finished still calls
/// `sqlite3_backup_finish`.
pub(crate) struct BackupJob {
    handle: NonNull<ffi::Backup>,
}

impl BackupJob {
    /// Runs up to `n_page` pages (negative for all remaining), returning the raw code so callers
    /// can tell `SQLITE_DONE` from plain success.
    pub(crate) fn step(&self, n_page: c_int) -> c_int {
        // SAFETY: the handle is valid until `finish`/drop, and `step` never invalidates it.
        unsafe { ffi::sqlite3_backup_step(self.handle.as_ptr(), n_page) }
    }

    /// Ends the backup, then forgets `self` so `Drop` never finishes the same handle twice.
    pub(crate) fn finish(self) -> Result<(), Code> {
        // SAFETY: `handle` came from a successful `backup_init`; `mem::forget` below is what
        // keeps this the only call that finishes it.
        let result = check(unsafe { ffi::sqlite3_backup_finish(self.handle.as_ptr()) });
        core::mem::forget(self);
        result
    }
}

impl Drop for BackupJob {
    fn drop(&mut self) {
        // SAFETY: only reached when `finish` was never called, since `finish` forgets `self`
        // first; `self.handle` is still valid and this is its only release.
        unsafe {
            ffi::sqlite3_backup_finish(self.handle.as_ptr());
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: `self.db` came from a successful open and is closed only here. Statements
        // borrow the connection, so all of them were finalized before this runs.
        unsafe { ffi::sqlite3_close_v2(self.db.as_ptr()) };
    }
}

/// A prepared statement, finalized on drop and unable to outlive its connection.
pub(crate) struct Statement<'c> {
    stmt: NonNull<ffi::Stmt>,
    _connection: PhantomData<&'c Connection>,
}

impl Statement<'_> {
    /// Binds `params` and steps to the end, clearing the bindings before their borrows end.
    pub(crate) fn run(&mut self, params: &[Param<'_>]) -> Result<(), Code> {
        let result = self.bind(params).and_then(|()| loop {
            match self.step() {
                ffi::SQLITE_ROW => {}
                ffi::SQLITE_DONE => break Ok(()),
                rc => break Err(Code::of(rc)),
            }
        });
        // SAFETY: `self.stmt` is a live statement owned by `self`.
        unsafe { ffi::sqlite3_reset(self.stmt.as_ptr()) };
        // SAFETY: as above. After this SQLite holds no pointer into `params`.
        unsafe { ffi::sqlite3_clear_bindings(self.stmt.as_ptr()) };
        result
    }

    fn step(&mut self) -> c_int {
        // SAFETY: `self.stmt` is a live statement, and every bound buffer outlives the step,
        // since `run` clears bindings before its borrows end.
        unsafe { ffi::sqlite3_step(self.stmt.as_ptr()) }
    }

    fn bind(&self, params: &[Param<'_>]) -> Result<(), Code> {
        let stmt = self.stmt.as_ptr();
        for (index, param) in (1..).zip(params) {
            let rc = match *param {
                // SAFETY: `stmt` is live and `index` counts from 1 as SQLite expects.
                Param::Null => unsafe { ffi::sqlite3_bind_null(stmt, index) },
                // SAFETY: as above.
                Param::Integer(v) => unsafe { ffi::sqlite3_bind_int64(stmt, index, v) },
                // SAFETY: as above.
                Param::Real(v) => unsafe { ffi::sqlite3_bind_double(stmt, index, v) },
                Param::Text(v) => {
                    let len = c_int::try_from(v.len()).expect("text fits an int");
                    // SAFETY: `v` is valid for `len` bytes, and SQLITE_STATIC (the `None`
                    // destructor) is sound because `run` clears the binding before `v`'s
                    // borrow ends.
                    unsafe {
                        ffi::sqlite3_bind_text(stmt, index, v.as_ptr().cast::<c_char>(), len, None)
                    }
                }
                Param::Blob(v) => {
                    let len = c_int::try_from(v.len()).expect("blob fits an int");
                    // SAFETY: as for text.
                    unsafe {
                        ffi::sqlite3_bind_blob(stmt, index, v.as_ptr().cast::<c_void>(), len, None)
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
            ffi::SQLITE_ROW => {}
            ffi::SQLITE_DONE => return Ok(None),
            rc => return Err(Code::of(rc)),
        }
        // SAFETY: the statement is live and positioned on a row.
        let columns = unsafe { ffi::sqlite3_column_count(self.stmt.as_ptr()) };
        Ok(Some((0..columns).map(|i| self.column(i)).collect()))
    }

    /// Column `i` of the current row, where `i` is below the column count.
    fn column(&self, i: c_int) -> Value {
        let stmt = self.stmt.as_ptr();
        // SAFETY: the statement is positioned on a row and `i` is in range, which holds for
        // every accessor below.
        match unsafe { ffi::sqlite3_column_type(stmt, i) } {
            // SAFETY: as above.
            ffi::SQLITE_INTEGER => Value::Integer(unsafe { ffi::sqlite3_column_int64(stmt, i) }),
            // SAFETY: as above.
            ffi::SQLITE_FLOAT => {
                Value::Real(unsafe { ffi::sqlite3_column_double(stmt, i) }.to_bits())
            }
            ffi::SQLITE_TEXT => {
                // SAFETY: as above. The pointer is fetched before its length, the order SQLite
                // documents for a stable result.
                let text = unsafe { ffi::sqlite3_column_text(stmt, i) };
                Value::Text(self.copy(text, i))
            }
            ffi::SQLITE_BLOB => {
                // SAFETY: as for text.
                let blob = unsafe { ffi::sqlite3_column_blob(stmt, i) }.cast::<u8>();
                Value::Blob(self.copy(blob, i))
            }
            _ => Value::Null,
        }
    }

    /// Copies the bytes `data` points at for column `i`, just fetched from the current row.
    fn copy(&self, data: *const u8, i: c_int) -> Vec<u8> {
        // SAFETY: the statement is on a row and `i` is in range, and asking for the length
        // after the pointer leaves the pointer valid.
        let len = unsafe { ffi::sqlite3_column_bytes(self.stmt.as_ptr(), i) };
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
        unsafe { ffi::sqlite3_finalize(self.stmt.as_ptr()) };
    }
}
