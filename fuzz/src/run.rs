//! One execution: write with one side, read with both, damage a copy, read that with both.

use core::ffi::{c_int, CStr};
use std::{
    ffi::CString,
    fmt::Write as _,
    fs,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{LazyLock, Mutex},
};

use crate::{
    db::{Code, Connection, Param, Value},
    ffi::{
        Api, SQLCIPHER, SQLITE3MC, SQLITE_OPEN_CREATE, SQLITE_OPEN_READONLY, SQLITE_OPEN_READWRITE,
    },
    input::{Algorithm, Case, Cell, Column, Config, Key, Op, Side, Table},
};

/// One observation of a dump. Two sides reading the same bytes must log the same records.
#[derive(Debug, PartialEq, Eq)]
enum Record {
    /// A page's decrypted content through `sqlite_dbpage`, without its reserved bytes.
    Page(i64, Vec<u8>),
    /// A result row of the named query.
    Row(&'static str, Vec<Value>),
    /// The named step failed, which ends the dump.
    Failed(&'static str, Code),
}

const TABLE_NAMES: [&str; 3] = ["t0", "t1", "t2"];

/// Runs `case`, panicking when the libraries disagree or the writer cannot read its own file.
///
/// # Panics
///
/// On a divergence, or when a library refuses a setting or step the harness generates as valid.
pub fn run(case: &Case) {
    // SQLCipher is compiled with no-op mutexes, and every execution reuses one directory.
    static SERIAL: Mutex<()> = Mutex::new(());
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // A case-derived seed, so the same case always draws the same salts and IVs on replay, but
    // different cases are not forced to start from the identical stream.
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&format!("{case:?}"), &mut hasher);
    crate::entropy::reset(std::hash::Hasher::finish(&hasher));

    let dir = WORKDIR.as_path();
    let clean = dir.join("clean.db");
    let damaged = dir.join("damaged.db");
    remove(&clean);
    remove(&damaged);

    let writer = case.writer;
    let reader = match writer {
        Side::SqlCipher => Side::Sqlite3mc,
        Side::Sqlite3mc => Side::SqlCipher,
    };
    write(writer, &clean, case);

    let own = dump(writer, &clean, &case.config);
    assert!(
        !own.iter().any(|r| matches!(r, Record::Failed(..)))
            && own.last()
                == Some(&Record::Row(
                    "integrity_check",
                    vec![Value::Text(b"ok".to_vec())]
                )),
        "{} cannot read back its own file for {case:#?}: {}",
        name(writer),
        describe(own.iter().rev().take(3)),
    );
    compare(
        case,
        "the clean file",
        writer,
        &own,
        reader,
        &dump(reader, &clean, &case.config),
    );

    let mut bytes = fs::read(&clean).expect("the clean file exists");
    let flips = &case.damage[..case.damage.len().min(Case::MAX_FLIPS)];
    if !bytes.is_empty() && !flips.is_empty() {
        let len = u64::try_from(bytes.len()).expect("file length fits u64");
        for flip in flips {
            let offset =
                usize::try_from(u64::from(flip.offset) % len).expect("offset is below the length");
            // SQLite3MC reads this salt from the file (upstream/sqlite3mc-sqlcipher-explicit-salt.md).
            if offset < 16 && case.config.explicit_salt_unused_by_sqlite3mc() {
                continue;
            }
            bytes[offset] ^= flip.mask;
        }
        fs::write(&damaged, &bytes).expect("the work directory is writable");
        let by_writer = dump(writer, &damaged, &case.config);
        let by_reader = dump(reader, &damaged, &case.config);
        compare(
            case,
            "the damaged file",
            writer,
            &by_writer,
            reader,
            &by_reader,
        );
    }

    remove(&clean);
    remove(&damaged);
}

const fn api(side: Side) -> &'static Api {
    match side {
        Side::SqlCipher => &SQLCIPHER,
        Side::Sqlite3mc => &SQLITE3MC,
    }
}

const fn name(side: Side) -> &'static str {
    match side {
        Side::SqlCipher => "SQLCipher",
        Side::Sqlite3mc => "SQLite3MC",
    }
}

/// A per-process directory on tmpfs where there is one.
static WORKDIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let shm = Path::new("/dev/shm");
    let base = if shm.is_dir() {
        shm.to_path_buf()
    } else {
        std::env::temp_dir()
    };
    let dir = base.join(format!("sqlite3mc-src-fuzz-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("the work directory can be created");
    dir
});

fn remove(db: &Path) {
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let mut path = db.as_os_str().to_owned();
        path.push(suffix);
        let _ = fs::remove_file(path);
    }
}

fn c_path(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("the work directory has no NUL")
}

fn sql(text: &str) -> CString {
    CString::new(text).expect("harness SQL has no NUL")
}

fn hex(bytes: &[u8], out: &mut String) {
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
}

fn key_bytes(key: &Key) -> Vec<u8> {
    match key {
        Key::Raw(key) => {
            let mut text = String::from("x'");
            hex(key, &mut text);
            text.push('\'');
            text.into_bytes()
        }
        Key::RawWithSalt { key, salt, .. } => {
            let mut text = String::from("x'");
            hex(key, &mut text);
            hex(salt, &mut text);
            text.push('\'');
            text.into_bytes()
        }
        Key::Passphrase { bytes, .. } => bytes.clone(),
    }
}

/// Applies `config` and the key, returning only a refused key as an observation.
fn configure(connection: &Connection<'_>, side: Side, config: &Config) -> Result<(), Code> {
    match side {
        Side::Sqlite3mc => configure_sqlite3mc(connection, config),
        Side::SqlCipher => configure_sqlcipher(connection, config),
    }
}

const fn sqlite3mc_algorithm(algorithm: Algorithm) -> c_int {
    match algorithm {
        Algorithm::Sha1 => 0,
        Algorithm::Sha256 => 1,
        Algorithm::Sha512 => 2,
    }
}

fn configure_sqlite3mc(connection: &Connection<'_>, config: &Config) -> Result<(), Code> {
    let cipher = connection.sqlite3mc_cipher_index(c"sqlcipher");
    assert_eq!(
        connection.sqlite3mc_config(c"cipher", cipher),
        cipher,
        "SQLite3MC refused its sqlcipher scheme"
    );
    let set = |param: &CStr, value: c_int| {
        let set = connection.sqlite3mc_config_cipher(c"sqlcipher", param, value);
        assert_eq!(set, value, "SQLite3MC refused {param:?} = {value}");
    };
    // `legacy` first, since it resets the other parameters to that version's defaults.
    set(c"legacy", c_int::from(config.compatibility));
    if let Some(page_size) = config.page_size {
        set(
            c"legacy_page_size",
            c_int::try_from(page_size).expect("page sizes fit an int"),
        );
    }
    if let Some(algorithm) = config.kdf_algorithm {
        set(c"kdf_algorithm", sqlite3mc_algorithm(algorithm));
    }
    if let Some(algorithm) = config.hmac_algorithm {
        set(c"hmac_algorithm", sqlite3mc_algorithm(algorithm));
    }
    if let Some(hmac) = config.hmac {
        set(c"hmac_use", c_int::from(hmac));
    }
    if let Key::Passphrase { kdf_iter, .. } = config.key {
        set(c"kdf_iter", c_int::from(kdf_iter));
    }
    if config.plaintext_header() > 0 {
        set(
            c"plaintext_header_size",
            c_int::from(config.plaintext_header()),
        );
    }
    connection.key(&key_bytes(&config.key))
}

fn configure_sqlcipher(connection: &Connection<'_>, config: &Config) -> Result<(), Code> {
    // SQLCipher ignores cipher pragmas until the key has created the codec.
    connection.key(&key_bytes(&config.key))?;
    let pragma = |text: String| {
        let result = connection.execute(&sql(&text), &[]);
        assert_eq!(result, Ok(()), "SQLCipher refused {text}");
    };
    pragma(format!(
        "PRAGMA cipher_compatibility = {}",
        config.compatibility
    ));
    if let Some(page_size) = config.page_size {
        pragma(format!("PRAGMA cipher_page_size = {page_size}"));
    }
    let hash = |algorithm| match algorithm {
        Algorithm::Sha1 => "SHA1",
        Algorithm::Sha256 => "SHA256",
        Algorithm::Sha512 => "SHA512",
    };
    if let Some(algorithm) = config.kdf_algorithm {
        pragma(format!(
            "PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_{}",
            hash(algorithm)
        ));
    }
    if let Some(algorithm) = config.hmac_algorithm {
        pragma(format!(
            "PRAGMA cipher_hmac_algorithm = HMAC_{}",
            hash(algorithm)
        ));
    }
    if let Some(hmac) = config.hmac {
        pragma(format!(
            "PRAGMA cipher_use_hmac = {}",
            if hmac { "ON" } else { "OFF" }
        ));
    }
    if let Key::Passphrase { kdf_iter, .. } = config.key {
        pragma(format!("PRAGMA kdf_iter = {kdf_iter}"));
    }
    if config.plaintext_header() > 0 {
        pragma(format!(
            "PRAGMA cipher_plaintext_header_size = {}",
            config.plaintext_header()
        ));
    }
    Ok(())
}

/// Bytes from a xorshift generator, so a blob is incompressible and unlike its neighbours.
fn blob(len: u16, seed: u8) -> Vec<u8> {
    let mut state = 0x9e37_79b9_u32 ^ u32::from(seed);
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect()
}

const fn column_name(column: Column) -> &'static str {
    match column {
        Column::I => "i",
        Column::R => "r",
        Column::T => "t",
        Column::B => "b",
    }
}

/// Owns the bytes a [`Cell`] binds, so the parameter can borrow them.
enum Owned<'a> {
    Borrowed(&'a Cell),
    Blob(Vec<u8>),
}

impl<'a> Owned<'a> {
    fn new(cell: &'a Cell) -> Self {
        match *cell {
            Cell::Blob { len, seed } => Self::Blob(blob(len, seed)),
            _ => Self::Borrowed(cell),
        }
    }

    fn param(&self) -> Param<'_> {
        match self {
            Self::Blob(bytes) => Param::Blob(bytes),
            Self::Borrowed(Cell::Null) => Param::Null,
            Self::Borrowed(Cell::Integer(v)) => Param::Integer(*v),
            Self::Borrowed(Cell::Real(v)) => Param::Real(*v),
            Self::Borrowed(Cell::Text(v)) => Param::Text(v),
            Self::Borrowed(Cell::Blob { .. }) => unreachable!("blobs are generated in `new`"),
        }
    }
}

/// Creates the database and runs the workload, whose steps are all valid SQL.
fn write(side: Side, path: &Path, case: &Case) {
    let connection = Connection::open(
        api(side),
        &c_path(path),
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
    )
    .unwrap_or_else(|code| panic!("{} cannot create a database: {code:?}", name(side)));
    if let Err(code) = configure(&connection, side, &case.config) {
        panic!("{} refused the key of a new database: {code:?}", name(side));
    }
    let mut created = [false; 3];
    // Tables created inside a transaction disappear again on rollback.
    let mut before_transaction: Option<[bool; 3]> = None;
    let run = |text: &str, params: &[Param<'_>], op: &Op| {
        if let Err(code) = connection.execute(&sql(text), params) {
            panic!(
                "{} failed {op:?} ({text}) with {code:?} for {case:#?}",
                name(side)
            );
        }
    };
    for op in case.ops.iter().take(Case::MAX_OPS) {
        let exists = |table: Table| created[table.index()];
        match op {
            Op::Create(table) => {
                let t = TABLE_NAMES[table.index()];
                run(
                    &format!("CREATE TABLE IF NOT EXISTS {t}(i INTEGER, r REAL, t TEXT, b BLOB)"),
                    &[],
                    op,
                );
                created[table.index()] = true;
            }
            Op::Index(table, column) if exists(*table) => {
                let (t, c) = (TABLE_NAMES[table.index()], column_name(*column));
                run(
                    &format!("CREATE INDEX IF NOT EXISTS {t}_{c} ON {t}({c})"),
                    &[],
                    op,
                );
            }
            Op::Insert(table, cells) if exists(*table) => {
                let owned = cells.each_ref().map(Owned::new);
                let params = owned.each_ref().map(Owned::param);
                let t = TABLE_NAMES[table.index()];
                run(
                    &format!("INSERT INTO {t}(i, r, t, b) VALUES (?1, ?2, ?3, ?4)"),
                    &params,
                    op,
                );
            }
            Op::Update(table, rowid, column, cell) if exists(*table) => {
                let owned = Owned::new(cell);
                let (t, c) = (TABLE_NAMES[table.index()], column_name(*column));
                let params = [owned.param(), Param::Integer(i64::from(*rowid))];
                run(
                    &format!("UPDATE {t} SET {c} = ?1 WHERE rowid = ?2"),
                    &params,
                    op,
                );
            }
            Op::Delete(table, rowid) if exists(*table) => {
                let t = TABLE_NAMES[table.index()];
                run(
                    &format!("DELETE FROM {t} WHERE rowid = ?1"),
                    &[Param::Integer(i64::from(*rowid))],
                    op,
                );
            }
            Op::Vacuum if before_transaction.is_none() => run("VACUUM", &[], op),
            Op::Begin if before_transaction.is_none() => {
                run("BEGIN", &[], op);
                before_transaction = Some(created);
            }
            Op::Commit if before_transaction.is_some() => {
                run("COMMIT", &[], op);
                before_transaction = None;
            }
            Op::Rollback => {
                if let Some(saved) = before_transaction.take() {
                    run("ROLLBACK", &[], op);
                    created = saved;
                }
            }
            _ => {}
        }
    }
    if before_transaction.is_some() {
        run("COMMIT", &[], &Op::Commit);
    }
}

/// Everything `side` can read from the file at `path`, up to the first failure.
fn dump(side: Side, path: &Path, config: &Config) -> Vec<Record> {
    let mut log = Vec::new();
    let connection = match Connection::open(api(side), &c_path(path), SQLITE_OPEN_READONLY) {
        Ok(connection) => connection,
        Err(code) => {
            log.push(Record::Failed("open", code));
            return log;
        }
    };
    if let Err(code) = configure(&connection, side, config) {
        log.push(Record::Failed("key", code));
        return log;
    }
    let result = pages(&connection, &mut log)
        .and_then(|()| rows(&connection, "sqlite_schema", c"SELECT type, name, tbl_name, rootpage, sql FROM sqlite_schema ORDER BY rowid", &mut log))
        .and_then(|()| {
            for (table, name) in Table::ALL.into_iter().zip(TABLE_NAMES) {
                let listed = log.iter().any(|r| matches!(r, Record::Row("sqlite_schema", row) if row.get(..2) == Some(&[Value::Text(b"table".to_vec()), Value::Text(name.as_bytes().to_vec())])));
                if listed {
                    let query = sql(&format!("SELECT rowid, * FROM {name} ORDER BY rowid"));
                    rows(&connection, TABLE_NAMES[table.index()], &query, &mut log)?;
                }
            }
            Ok(())
        })
        .and_then(|()| rows(&connection, "integrity_check", c"PRAGMA integrity_check", &mut log));
    if let Err((stage, code)) = result {
        log.push(Record::Failed(stage, code));
    }
    log
}

type Step = Result<(), (&'static str, Code)>;

fn rows(
    connection: &Connection<'_>,
    stage: &'static str,
    query: &CStr,
    log: &mut Vec<Record>,
) -> Step {
    let mut statement = connection.prepare(query).map_err(|code| (stage, code))?;
    while let Some(row) = statement.next_row().map_err(|code| (stage, code))? {
        log.push(Record::Row(stage, row));
    }
    Ok(())
}

/// Logs every page's content area, cutting the reserved bytes page 1's header byte 20 names.
fn pages(connection: &Connection<'_>, log: &mut Vec<Record>) -> Step {
    const STAGE: &str = "sqlite_dbpage";
    let mut statement = connection
        .prepare(c"SELECT pgno, data FROM sqlite_dbpage ORDER BY pgno")
        .map_err(|code| (STAGE, code))?;
    let mut reserved = 0;
    while let Some(row) = statement.next_row().map_err(|code| (STAGE, code))? {
        let (pgno, mut data) = match <[Value; 2]>::try_from(row) {
            Ok([Value::Integer(pgno), Value::Blob(data)]) => (pgno, data),
            Ok(other) => panic!("sqlite_dbpage returned {other:?}"),
            Err(row) => panic!("sqlite_dbpage returned {} columns", row.len()),
        };
        if pgno == 1 {
            reserved = data.get(20).map_or(0, |&r| usize::from(r));
        }
        data.truncate(data.len().saturating_sub(reserved));
        log.push(Record::Page(pgno, data));
    }
    Ok(())
}

fn compare(case: &Case, file: &str, a: Side, a_log: &[Record], b: Side, b_log: &[Record]) {
    if a_log == b_log {
        return;
    }
    let at = a_log.iter().zip(b_log).take_while(|(x, y)| x == y).count();
    let (sqlcipher, sqlite3mc) = if a == Side::SqlCipher {
        (a_log, b_log)
    } else {
        (b_log, a_log)
    };
    if case.config.reserved() > 16
        && swallowed_hmac_failure(
            at,
            case.config.plaintext_header() > 0,
            sqlcipher.get(at),
            sqlite3mc.get(at),
        )
    {
        return;
    }
    panic!(
        "{} and {} disagree on {file} from record {at} (of {} and {}).\n{}:{}\n{}:{}\nfor {case:#?}",
        name(a),
        name(b),
        a_log.len(),
        b_log.len(),
        name(a),
        describe(&a_log[at..]),
        name(b),
        describe(&b_log[at..]),
    );
}

/// SQLCipher 4.19.0 zero-fills a page failing its HMAC (upstream/sqlcipher-swallowed-hmac-failure.md).
fn swallowed_hmac_failure(
    at: usize,
    plaintext_header: bool,
    sqlcipher: Option<&Record>,
    sqlite3mc: Option<&Record>,
) -> bool {
    match (sqlcipher, sqlite3mc) {
        (Some(Record::Page(_, data)), Some(Record::Failed("sqlite_dbpage", Code(11)))) => {
            data.iter().all(|&b| b == 0)
        }
        (
            Some(Record::Failed("sqlite_dbpage", Code(11))),
            Some(Record::Failed("sqlite_dbpage", Code(26))),
        ) => at == 0 && plaintext_header,
        _ => false,
    }
}

/// Up to six records, one per line, each cut to a readable length.
fn describe<'r>(records: impl IntoIterator<Item = &'r Record>) -> String {
    let mut out = String::new();
    for record in records.into_iter().take(6) {
        let start = out.len();
        out.push_str("\n  ");
        match record {
            Record::Page(pgno, data) => {
                let _ = write!(out, "page {pgno}, {} bytes, starting ", data.len());
                hex(&data[..data.len().min(32)], &mut out);
            }
            Record::Row(stage, row) => {
                let _ = write!(out, "{stage} row {row:?}");
                out.truncate(start + 200);
            }
            Record::Failed(stage, code) => {
                let _ = write!(out, "{stage} failed with {code:?}");
            }
        }
    }
    if out.is_empty() {
        out.push_str(" nothing");
    }
    out
}
