//! SQLite3MC built by sqlite-wasm-rs from this crate encrypts, reopens, and rejects a wrong key.
use sqlite_wasm_rs as ffi;
use sqlite_wasm_rs::vfs::memvfs::MemVfsUtil;
use sqlite_wasm_rs::vfs::transfer::DbTransfer;
use std::ffi::{CStr, CString};
use wasm_bindgen_test::wasm_bindgen_test;

struct Db(*mut ffi::sqlite3);

impl Db {
    fn open(name: &str) -> Self {
        let name = CString::new(name).unwrap();
        let mut db = std::ptr::null_mut();
        let flags = ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE;
        let rc = unsafe { ffi::sqlite3_open_v2(name.as_ptr(), &mut db, flags, std::ptr::null()) };
        assert_eq!(rc, ffi::SQLITE_OK);
        Self(db)
    }

    fn exec(&self, sql: &str) -> i32 {
        let sql = CString::new(sql).unwrap();
        unsafe {
            ffi::sqlite3_exec(
                self.0,
                sql.as_ptr(),
                None,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }
    }

    fn text(&self, sql: &str) -> Option<String> {
        let sql = CString::new(sql).unwrap();
        let mut stmt = std::ptr::null_mut();
        unsafe {
            let rc =
                ffi::sqlite3_prepare_v2(self.0, sql.as_ptr(), -1, &mut stmt, std::ptr::null_mut());
            if rc != ffi::SQLITE_OK {
                return None;
            }
            let row = (ffi::sqlite3_step(stmt) == ffi::SQLITE_ROW).then(|| {
                CStr::from_ptr(ffi::sqlite3_column_text(stmt, 0).cast())
                    .to_string_lossy()
                    .into_owned()
            });
            ffi::sqlite3_finalize(stmt);
            row
        }
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        unsafe { ffi::sqlite3_close(self.0) };
    }
}

#[wasm_bindgen_test]
fn sqlite3mc_encrypts_and_rejects_a_wrong_key() {
    assert_eq!(unsafe { ffi::sqlite3_initialize() }, ffi::SQLITE_OK);
    let util = unsafe { MemVfsUtil::get() }.unwrap();
    {
        let db = Db::open("mc.db");
        let version = db.text("SELECT sqlite3mc_version()").unwrap();
        assert!(
            version.ends_with(sqlite3mc_src::SQLITE3MC_VERSION),
            "{version}"
        );
        assert_eq!(
            db.exec("PRAGMA key = 'correct horse battery staple'"),
            ffi::SQLITE_OK
        );
        let rc = db.exec("CREATE TABLE t(v TEXT); INSERT INTO t VALUES ('sqlite3mc-secret')");
        assert_eq!(rc, ffi::SQLITE_OK);
    }
    let bytes = util.export_db("mc.db").unwrap();
    assert!(!bytes.is_empty());
    assert!(!bytes.starts_with(b"SQLite format 3"));
    assert!(!bytes.windows(16).any(|w| w == b"sqlite3mc-secret"));

    let right = Db::open("mc.db");
    assert_eq!(
        right.exec("PRAGMA key = 'correct horse battery staple'"),
        ffi::SQLITE_OK
    );
    assert_eq!(
        right.text("SELECT v FROM t").as_deref(),
        Some("sqlite3mc-secret")
    );

    let wrong = Db::open("mc.db");
    assert_eq!(wrong.exec("PRAGMA key = 'wrong'"), ffi::SQLITE_OK);
    assert_eq!(
        wrong.exec("SELECT count(*) FROM sqlite_schema"),
        ffi::SQLITE_NOTADB
    );
}
