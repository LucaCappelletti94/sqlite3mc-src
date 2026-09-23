//! The vendored files agree with the versions the crate declares.

use sqlite3mc_src::{
    source_dir, EXTENSION_HEADER_FILE, HEADER_FILE, SOURCE_FILE, SQLITE3MC_VERSION, SQLITE_VERSION,
};

fn header() -> String {
    std::fs::read_to_string(source_dir().join(HEADER_FILE)).expect("vendored header is readable")
}

#[test]
fn every_vendored_file_is_present() {
    for file in [
        SOURCE_FILE,
        HEADER_FILE,
        EXTENSION_HEADER_FILE,
        "LICENSE",
        "SHA256SUMS",
    ] {
        assert!(source_dir().join(file).is_file(), "{file} missing");
    }
}

#[test]
fn header_carries_the_declared_sqlite3mc_version() {
    let expected = format!("\"SQLite3 Multiple Ciphers {SQLITE3MC_VERSION}\"");
    assert!(
        header()
            .lines()
            .any(|line| line.starts_with("#define SQLITE3MC_VERSION_STRING")
                && line.contains(&expected)),
        "header does not declare {expected}"
    );
}

#[test]
fn header_carries_the_declared_sqlite_version() {
    let expected = format!("\"{SQLITE_VERSION}\"");
    assert!(
        header()
            .lines()
            .any(|line| line.starts_with("#define SQLITE_VERSION ") && line.contains(&expected)),
        "header does not declare SQLite {SQLITE_VERSION}"
    );
}

#[test]
fn crate_version_encodes_the_sqlite3mc_release() {
    let mut parts = SQLITE3MC_VERSION
        .split('.')
        .map(|part| part.parse::<u64>().unwrap());
    let (major, minor, patch) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    assert_eq!(
        env!("CARGO_PKG_VERSION_MAJOR").parse::<u64>().unwrap(),
        major * 100 + minor
    );
    assert_eq!(
        env!("CARGO_PKG_VERSION_MINOR").parse::<u64>().unwrap(),
        patch
    );
}
