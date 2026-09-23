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
fn crate_version_encodes_the_release() {
    let mut parts = SQLITE3MC_VERSION
        .split('.')
        .map(|part| part.parse::<u64>().unwrap());
    let (major, minor, patch) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let (numbers, metadata) = env!("CARGO_PKG_VERSION")
        .split_once('+')
        .expect("the crate version carries build metadata");
    assert!(
        numbers.starts_with(&format!("{}.{patch}.", major * 100 + minor)),
        "{numbers} does not encode SQLite3MC {SQLITE3MC_VERSION}"
    );
    assert_eq!(
        metadata,
        format!("sqlite3mc-{SQLITE3MC_VERSION}-sqlite-{SQLITE_VERSION}")
    );
}
