//! Checks the compiled amalgamation reports the versions `sqlite3mc-src` declares.

use std::ffi::{c_char, CStr};

unsafe extern "C" {
    fn sqlite3_libversion() -> *const c_char;
    fn sqlite3mc_version() -> *const c_char;
}

fn main() {
    // Both return pointers to static NUL-terminated strings.
    let sqlite = unsafe { CStr::from_ptr(sqlite3_libversion()) };
    let mc = unsafe { CStr::from_ptr(sqlite3mc_version()) };
    let expected_mc = format!(
        "SQLite3 Multiple Ciphers {}",
        sqlite3mc_src::SQLITE3MC_VERSION
    );
    assert_eq!(sqlite.to_str(), Ok(sqlite3mc_src::SQLITE_VERSION));
    assert_eq!(mc.to_str(), Ok(expected_mc.as_str()));
    println!(
        "{expected_mc} on SQLite {}, compiled from {}",
        sqlite3mc_src::SQLITE_VERSION,
        sqlite3mc_src::source_dir().display()
    );
}
