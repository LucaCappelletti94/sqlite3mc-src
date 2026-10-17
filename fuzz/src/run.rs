//! One execution: write, read back, damage a copy, read that, through SQLite3MC's own ciphers.

use core::ffi::{c_int, CStr};
use std::{
    ffi::CString,
    fmt::Write as _,
    fs,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{LazyLock, Mutex, MutexGuard},
};

use crate::{
    db::{Code, Connection, Param, Value},
    ffi::{SQLITE_DONE, SQLITE_OPEN_CREATE, SQLITE_OPEN_READONLY, SQLITE_OPEN_READWRITE},
    input::{
        Algorithm, AttachCase, AttachedDb, BackupCase, Cell, Cipher, Column, NativeCase,
        NativeConfig, NativeKey, Op, PageSize, RekeyAction, RekeyCase, Table, WalCase,
        MAX_ATTACHED, MAX_ATTACH_ROWS, MAX_FLIPS, MAX_OPS,
    },
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

/// `CIPHER_PAGE1_OFFSET` in `sqlite3mc_amalgamation.c`: how many bytes at the start of page 1
/// every native scheme leaves outside its AEAD coverage, independent of `plaintext_header_size`.
const CIPHER_PAGE1_OFFSET: usize = 24;

/// The page size the native targets see: they never set `PRAGMA page_size`.
const PAGE_SIZE: usize = 4096;

/// Whether `log` is a full, successful dump: no failed step, ending in an `ok` integrity check.
fn clean_read(log: &[Record]) -> bool {
    !log.iter().any(|r| matches!(r, Record::Failed(..)))
        && log.last()
            == Some(&Record::Row(
                "integrity_check",
                vec![Value::Text(b"ok".to_vec())],
            ))
}

/// Runs `case` against one of SQLite3MC's native cipher schemes.
///
/// Panics on a failed round-trip, a wrong key that still reads back the right content, or, for a
/// scheme that authenticates its pages, damage that scheme failed to catch.
///
/// # Panics
///
/// When SQLite3MC refuses a setting or step the harness generates as valid, or an oracle fails.
pub fn run_native(case: &NativeCase) {
    static SERIAL: Mutex<()> = Mutex::new(());
    let _serial = begin_run(&SERIAL);

    let dir = WORKDIR.as_path();
    let clean = dir.join("native-clean.db");
    let damaged = dir.join("native-damaged.db");
    remove(&clean);
    remove(&damaged);

    let cipher = case.config.cipher;
    let connection = open_native(&clean, &case.config, "database");
    run_workload(&connection, "SQLite3MC", &case.ops, case);
    drop(connection);

    let own = dump_native(&clean, &case.config);
    assert!(
        clean_read(&own),
        "SQLite3MC cannot read back its own {} file for {case:#?}: {}",
        cipher.name(),
        describe(own.iter().rev().take(3)),
    );

    // An empty database (no table ever created) reads back as just the `ok` integrity check for
    // any key, correct or not, so the wrong key can only be judged once there is real content. A
    // wrong key equivalent to the real one (same material, or a `kdf_iter` the cipher ignores)
    // proves nothing either.
    let key_len = cipher.key_len(case.config.aegis_algorithm_256);
    if !native_keys_equivalent(&case.wrong_key, &case.config.key, &case.config, key_len)
        && own.len() > 1
    {
        let mut wrong_config = case.config.clone();
        wrong_config.key = case.wrong_key.clone();
        let wrong = dump_native(&clean, &wrong_config);
        assert_ne!(
            wrong,
            own,
            "SQLite3MC's wrong key read back the same {} content for {case:#?}: {}",
            cipher.name(),
            describe(wrong.iter().rev().take(3)),
        );
    }

    if case.config.authenticated() {
        let original = fs::read(&clean).expect("the clean file exists");
        let mut bytes = original.clone();
        let flips = &case.damage[..case.damage.len().min(MAX_FLIPS)];
        // Page 1's unauthenticated prefix (the stored salt, then the SQLite header bytes an
        // unencrypted reader still needs) is CIPHER_PAGE1_OFFSET by default, or the whole
        // configured plaintext header when that is larger, for every native scheme regardless
        // (the same "bytes 16 through 23 usually not encrypted" limitation the project's own
        // docs state); tampering it is never expected to be caught.
        let unauthenticated =
            usize::from(case.config.plaintext_header_size.unwrap_or(0)).max(CIPHER_PAGE1_OFFSET);
        // `sqlcipher` with a SHA1 HMAC stores its digest in a 32-byte per-page slot but verifies
        // only the first 20 bytes, so each page's last 12 slot bytes are unauthenticated.
        let page_pad = usize::from(
            cipher == Cipher::SqlCipher && case.config.hmac_algorithm == Some(Algorithm::Sha1),
        ) * 12;
        if !bytes.is_empty() && !flips.is_empty() {
            let len = u64::try_from(bytes.len()).expect("file length fits u64");
            for flip in flips {
                let offset = usize::try_from(u64::from(flip.offset) % len)
                    .expect("offset is below the length");
                if offset < unauthenticated
                    || (page_pad > 0 && offset % PAGE_SIZE >= PAGE_SIZE - page_pad)
                {
                    continue;
                }
                bytes[offset] ^= flip.mask;
            }
            // A flip whose mask is 0, whose only set bits already matched, or that landed in the
            // unauthenticated region above and was skipped, changes nothing.
            if bytes != original {
                fs::write(&damaged, &bytes).expect("the work directory is writable");
                let tampered = dump_native(&damaged, &case.config);
                assert!(
                    !clean_read(&tampered),
                    "SQLite3MC's {} scheme accepted damage undetected for {case:#?}: {}",
                    cipher.name(),
                    describe(tampered.iter().rev().take(3)),
                );
            }
        }
    }

    remove(&clean);
    remove(&damaged);
}

/// Everything SQLite3MC can read back from `path` with `config`'s key, up to the first failure.
fn dump_native(path: &Path, config: &NativeConfig) -> Vec<Record> {
    dump(path, |c| configure_native(c, config))
}

/// Runs `case` against SQLite3MC's rekey support.
///
/// Writes under the original key, rekeys on the same connection, writes more, then round-trips
/// under the result and confirms the original key no longer reads it (`ChangeKey`; `Decrypt`'s
/// own result needs no such check, there being no key left to compare against).
///
/// # Panics
///
/// When SQLite3MC refuses a setting, a step, or the rekey itself that the harness generates as
/// valid, or an oracle fails.
pub fn run_rekey(case: &RekeyCase) {
    static SERIAL: Mutex<()> = Mutex::new(());
    let _serial = begin_run(&SERIAL);

    let dir = WORKDIR.as_path();
    let clean = dir.join("rekey.db");
    remove(&clean);

    let cipher = case.config.cipher;
    let connection = open_native(&clean, &case.config, "database");
    run_workload(&connection, "SQLite3MC", &case.ops_before, case);

    let key_len = cipher.key_len(case.config.aegis_algorithm_256);
    let new_key_bytes = match &case.action {
        RekeyAction::ChangeKey(key) => native_key_bytes(key, key_len),
        RekeyAction::Decrypt => Vec::new(),
    };
    // SQLite3MC consumes pending `sqlite3mc_config`/`sqlite3mc_config_cipher` state at every
    // key-applying call, `sqlite3_rekey` included, not just the original `sqlite3_key`. A value
    // staged only once, before the connection's first key, does not carry over to a later
    // rekey, so re-stage immediately before this call, using the new key's own `kdf_iter` when
    // it carries one (`utelle/SQLite3MultipleCiphers` issue #236 documents the same requirement
    // for `PRAGMA` sequences).
    let mut rekey_config = case.config.clone();
    if let RekeyAction::ChangeKey(new_key) = &case.action {
        rekey_config.key = new_key.clone();
    }
    stage_cipher(&connection, &rekey_config);
    if let Err(code) = connection.rekey(&new_key_bytes) {
        panic!(
            "SQLite3MC refused to rekey a {} database: {code:?} for {case:#?}",
            cipher.name()
        );
    }

    run_workload(&connection, "SQLite3MC (post-rekey)", &case.ops_after, case);
    drop(connection);

    let after_config = match &case.action {
        RekeyAction::ChangeKey(key) => {
            let mut config = case.config.clone();
            config.key = key.clone();
            Some(config)
        }
        RekeyAction::Decrypt => None,
    };
    let own = after_config.as_ref().map_or_else(
        || dump(&clean, |_| Ok(())),
        |config| dump_native(&clean, config),
    );
    assert!(
        clean_read(&own),
        "SQLite3MC cannot read back its own rekeyed {} file for {case:#?}: {}",
        cipher.name(),
        describe(own.iter().rev().take(3)),
    );

    // An empty database reads back as just the `ok` integrity check for any key, correct or not
    // (see run_native's own identical guard), and a pre-rekey key equivalent to the new one
    // proves nothing either.
    if let RekeyAction::ChangeKey(new_key) = &case.action {
        if !native_keys_equivalent(&case.config.key, new_key, &case.config, key_len)
            && own.len() > 1
        {
            let old = dump_native(&clean, &case.config);
            assert_ne!(
                old,
                own,
                "SQLite3MC's pre-rekey key still read back the rekeyed {} content for {case:#?}: {}",
                cipher.name(),
                describe(old.iter().rev().take(3)),
            );
        }
    }

    remove(&clean);
}

/// Runs `case` against SQLite3MC's `journal_mode=WAL` support.
///
/// Writes under WAL, optionally checkpoints, closes, optionally truncates the `-wal` file to
/// simulate a crash mid-write, then reopens and confirms the database still reads back cleanly:
/// `journal_mode=WAL` never excuses `SQLITE_NOTADB` or a failed `integrity_check`, truncation or
/// not, only losing the most recent, uncheckpointed writes is acceptable.
///
/// # Panics
///
/// When SQLite3MC refuses a setting or step the harness generates as valid, or the oracle fails.
pub fn run_wal(case: &WalCase) {
    static SERIAL: Mutex<()> = Mutex::new(());
    let _serial = begin_run(&SERIAL);

    let dir = WORKDIR.as_path();
    let clean = dir.join("wal.db");
    remove(&clean);

    let cipher = case.config.cipher;
    let connection = open_native(&clean, &case.config, "database");
    let legacy_wal = c_int::from(case.legacy_wal);
    assert_eq!(
        connection.sqlite3mc_config(c"mc_legacy_wal", legacy_wal),
        legacy_wal,
        "SQLite3MC refused mc_legacy_wal = {legacy_wal}"
    );
    if let Err(code) = connection.execute(c"PRAGMA journal_mode=WAL", &[]) {
        panic!(
            "SQLite3MC refused WAL journal mode for a {} database: {code:?}",
            cipher.name()
        );
    }
    run_workload(&connection, "SQLite3MC", &case.ops, case);
    if let Some(checkpoint) = case.checkpoint {
        let text = sql(&format!("PRAGMA wal_checkpoint({})", checkpoint.name()));
        if let Err(code) = connection.execute(&text, &[]) {
            panic!(
                "SQLite3MC refused a {} checkpoint on a {} database: {code:?}",
                checkpoint.name(),
                cipher.name()
            );
        }
    }
    drop(connection);

    if case.truncate_wal_tail > 0 {
        let mut wal_path = clean.as_os_str().to_owned();
        wal_path.push("-wal");
        if let Ok(bytes) = fs::read(&wal_path) {
            let keep = bytes
                .len()
                .saturating_sub(usize::from(case.truncate_wal_tail));
            if keep < bytes.len() {
                fs::write(&wal_path, &bytes[..keep]).expect("the work directory is writable");
            }
        }
    }

    let own = dump_native(&clean, &case.config);
    assert!(
        clean_read(&own),
        "SQLite3MC cannot read back its own {} WAL-mode file for {case:#?}: {}",
        cipher.name(),
        describe(own.iter().rev().take(3)),
    );

    remove(&clean);
}

/// Runs `case` against SQLite3MC's `ATTACH DATABASE` support.
///
/// Each attached database is first written standalone, with its own true cipher and key, exactly
/// as if some earlier, unrelated session had created it. Only then does a main connection attach
/// up to [`MAX_ATTACHED`] of them, each through a correct key, a wrong one, or an omitted one
/// that inherits the main connection's current codec, plus an optional `VACUUM`, a cross-database
/// copy, and a detach/reattach cycle. Closes everything, then reopens every database's own file
/// standalone with its own true config: regardless of what happened to it while attached, it must
/// still read back cleanly.
///
/// # Panics
///
/// When SQLite3MC refuses a setting or step the harness generates as valid, or a database's own
/// file fails to read back cleanly afterward.
pub fn run_attach(case: &AttachCase) {
    static SERIAL: Mutex<()> = Mutex::new(());
    let _serial = begin_run(&SERIAL);

    let dir = WORKDIR.as_path();
    let main_path = dir.join("attach-main.db");
    let attached_count = case.attached.len().min(MAX_ATTACHED);
    let attached_paths: Vec<PathBuf> = (0..attached_count)
        .map(|index| dir.join(format!("attach-{index}.db")))
        .collect();
    remove(&main_path);
    for path in &attached_paths {
        remove(path);
    }

    for (path, attached) in attached_paths.iter().zip(case.attached.iter()) {
        write_native(
            path,
            &attached.written,
            usize::from(attached.rows).min(MAX_ATTACH_ROWS),
        );
    }

    let main_cipher = case.main.cipher;
    let connection = open_native(&main_path, &case.main, "main database");
    if let Err(code) = connection.execute(c"CREATE TABLE t0(i INTEGER)", &[]) {
        panic!(
            "SQLite3MC refused to create main's own {} table: {code:?}",
            main_cipher.name()
        );
    }
    for i in 0..usize::from(case.main_rows).min(MAX_ATTACH_ROWS) {
        let row = i64::try_from(i).expect("row indices stay far below i64::MAX");
        if let Err(code) =
            connection.execute(c"INSERT INTO t0(i) VALUES (?1)", &[Param::Integer(row)])
        {
            panic!(
                "SQLite3MC refused to insert into main's own {} table: {code:?}",
                main_cipher.name()
            );
        }
    }

    for (index, attached) in case.attached.iter().take(MAX_ATTACHED).enumerate() {
        let path_str = attached_paths[index]
            .to_str()
            .expect("the work directory is valid UTF-8");
        exercise_attached(
            &connection,
            index,
            attached,
            case.cross_copy,
            case.detach_reattach,
            path_str,
        );
    }
    drop(connection);

    let own = dump_native(&main_path, &case.main);
    assert!(
        clean_read(&own),
        "SQLite3MC cannot read back its own {} main database after an ATTACH session for {case:#?}: {}",
        main_cipher.name(),
        describe(own.iter().rev().take(3)),
    );

    for (index, attached) in case.attached.iter().take(MAX_ATTACHED).enumerate() {
        // A wrong key, or a wrong cipher parameter even with the same key bytes, that `VACUUM`
        // or the cross-database copy then actually wrote through is not a defect: an
        // unauthenticated legacy scheme has no integrity check to catch it, so the file has
        // legitimately become whatever that wrong configuration wrote, the same way
        // `NativeCase`'s own wrong-key oracle only ever reads under a wrong key, never writes.
        // Only a database attached with its own true key is expected to stay recoverable under
        // it; a sibling's mishap corrupting THIS database's own correctly-keyed file would still
        // be caught here, which is the actual cross-database isolation this harness checks for.
        let correctly_keyed = attached.attach_key.as_ref() == Some(&attached.written)
            || (attached.attach_key.is_none() && case.main == attached.written);
        if !correctly_keyed {
            continue;
        }
        let dump = dump_native(&attached_paths[index], &attached.written);
        assert!(
            clean_read(&dump),
            "SQLite3MC corrupted attached database {index}'s own {} file during an ATTACH session for {case:#?}: {}",
            attached.written.cipher.name(),
            describe(dump.iter().rev().take(3)),
        );
    }

    remove(&main_path);
    for path in &attached_paths {
        remove(path);
    }
}

/// Creates and keys a brand-new native-scheme file at `path` standalone, with `rows` rows in its
/// own `t0` table, before anything else ever attaches it. Gives an [`AttachedDb`] real, known
/// prior content so attaching it later with the wrong key, or an inherited one, is an actual
/// mismatch and not just an empty file taking on whatever key first touches it.
fn write_native(path: &Path, config: &NativeConfig, rows: usize) {
    remove(path);
    let connection = open_native(path, config, "file");
    if let Err(code) = connection.execute(c"CREATE TABLE t0(i INTEGER)", &[]) {
        panic!(
            "SQLite3MC refused to create a table in a new {} file: {code:?}",
            config.cipher.name()
        );
    }
    for i in 0..rows {
        let row = i64::try_from(i).expect("row indices stay far below i64::MAX");
        if let Err(code) =
            connection.execute(c"INSERT INTO t0(i) VALUES (?1)", &[Param::Integer(row)])
        {
            panic!(
                "SQLite3MC refused to insert into a new {} file: {code:?}",
                config.cipher.name()
            );
        }
    }
}

/// Attaches one [`AttachedDb`] to `connection` as `db1`/`db2` (`index` 0 or otherwise) and
/// exercises it: an optional `VACUUM`, and, for the first attached database only, a
/// cross-database copy from main and a detach/reattach cycle using its own true key. Everything
/// after a failed `ATTACH` is skipped; every other step is tolerated to fail, a wrong or
/// inherited key means they are expected to.
fn exercise_attached(
    connection: &Connection,
    index: usize,
    attached: &AttachedDb,
    cross_copy: bool,
    detach_reattach: bool,
    path_str: &str,
) {
    let db_name = if index == 0 { "db1" } else { "db2" };
    if !attach(connection, db_name, path_str, attached.attach_key.as_ref()) {
        return;
    }
    if attached.vacuum {
        let _ = connection.execute(&sql(&format!("VACUUM {db_name}")), &[]);
    }
    if index == 0 && cross_copy {
        let _ = connection.execute(
            &sql(&format!(
                "INSERT INTO {db_name}.t0(i) SELECT i FROM main.t0"
            )),
            &[],
        );
    }
    if index == 0
        && detach_reattach
        && connection
            .execute(&sql(&format!("DETACH DATABASE {db_name}")), &[])
            .is_ok()
    {
        attach(connection, db_name, path_str, Some(&attached.written));
    }
}

/// Runs `case` against SQLite3MC's `sqlite3_backup_*` API.
///
/// Writes a source and, separately, a destination (which may carry unrelated content of its
/// own), each with its own cipher, key, and `PRAGMA page_size`, then backs the source up into the
/// destination. When `sqlite3_backup_init`'s own compatibility guard (`sqlite3mcIsBackupSupported`)
/// refuses the pair, there is nothing further to check: that is the guard working as intended.
/// That guard still lets pairs disagreeing on reserved bytes through, and such a backup corrupts the
/// destination (`upstream/sqlite3mc-backup-guard-ignores-reserve.md`). So only a pair laid out
/// identically, every cipher setting but the key and the `PRAGMA page_size` equal, has to reopen
/// cleanly with the destination's own true key after the backup reports full success. A failure
/// there is the defect `utelle/SQLite3MultipleCiphers` issue #158 described, and exactly what this
/// harness exists to catch a recurrence of.
///
/// # Panics
///
/// When SQLite3MC refuses a setting or step the harness generates as valid, or a backup between
/// two identically laid out databases reported full success and left an unreadable destination.
pub fn run_backup(case: &BackupCase) {
    static SERIAL: Mutex<()> = Mutex::new(());
    let _serial = begin_run(&SERIAL);

    let dir = WORKDIR.as_path();
    let src_path = dir.join("backup-src.db");
    let dest_path = dir.join("backup-dest.db");
    remove(&src_path);
    remove(&dest_path);

    let src = open_for_backup(&src_path, &case.src, case.src_page_size, &case.src_ops);
    let dest = open_for_backup(&dest_path, &case.dest, case.dest_page_size, &case.dest_ops);

    if let Some(job) = dest.backup_init(c"main", &src, c"main") {
        let step_rc = job.step(-1);
        let finish_result = job.finish();
        if step_rc == SQLITE_DONE
            && finish_result.is_ok()
            && case.src_page_size == case.dest_page_size
            && case.src.same_layout(&case.dest)
        {
            drop(src);
            drop(dest);
            let dump = dump_native(&dest_path, &case.dest);
            assert!(
                clean_read(&dump),
                "SQLite3MC's sqlite3_backup_init let through, and backup_step/backup_finish \
                 reported success for, a backup into its own {} destination that cannot be read \
                 back for {case:#?}: {}",
                case.dest.cipher.name(),
                describe(dump.iter().rev().take(3)),
            );
        }
    }

    remove(&src_path);
    remove(&dest_path);
}

/// Opens a new SQLite3MC file at `path`, stages and applies `config`'s cipher and key, sets
/// `page_size` through `PRAGMA page_size` first when given, then runs `ops`.
fn open_for_backup(
    path: &Path,
    config: &NativeConfig,
    page_size: Option<PageSize>,
    ops: &[Op],
) -> Connection {
    let connection = open_native(path, config, "file");
    if let Some(page_size) = page_size {
        let text = sql(&format!("PRAGMA page_size={}", page_size.get()));
        if let Err(code) = connection.execute(&text, &[]) {
            panic!(
                "SQLite3MC refused PRAGMA page_size={} on a new {} file: {code:?}",
                page_size.get(),
                config.cipher.name()
            );
        }
    }
    run_workload(&connection, "SQLite3MC", ops, config);
    connection
}

/// Runs `ATTACH DATABASE path_str AS db_name`, staging `attach_key`'s cipher and supplying its
/// key when given, omitting the `KEY` clause entirely otherwise (which SQLite3MC resolves by
/// copying the main database's own current codec verbatim). Returns whether it succeeded.
fn attach(
    connection: &Connection,
    db_name: &str,
    path_str: &str,
    attach_key: Option<&NativeConfig>,
) -> bool {
    let Some(stage_config) = attach_key else {
        return connection
            .execute(
                &sql(&format!("ATTACH DATABASE ?1 AS {db_name}")),
                &[Param::Text(path_str)],
            )
            .is_ok();
    };
    stage_cipher(connection, stage_config);
    let key_bytes = native_key_bytes(
        &stage_config.key,
        stage_config
            .cipher
            .key_len(stage_config.aegis_algorithm_256),
    );
    connection
        .execute(
            &sql(&format!("ATTACH DATABASE ?1 AS {db_name} KEY ?2")),
            &[Param::Text(path_str), Param::Blob(&key_bytes)],
        )
        .is_ok()
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

/// Locks `serial` so the fixed file names in the shared work directory see one run at a time.
/// The guard must stay alive for the whole run.
fn begin_run(serial: &Mutex<()>) -> MutexGuard<'_, ()> {
    let guard = serial
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
}

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

const fn sqlite3mc_algorithm(algorithm: Algorithm) -> c_int {
    match algorithm {
        Algorithm::Sha1 => 0,
        Algorithm::Sha256 => 1,
        Algorithm::Sha512 => 2,
    }
}

/// `key`'s bytes, truncated to `key_len` where that is shorter than the form's own natural
/// length, matching what [`Cipher::key_len`] says the scheme actually consumes.
fn native_key_bytes(key: &NativeKey, key_len: usize) -> Vec<u8> {
    match key {
        NativeKey::Raw(key) => {
            let mut text = String::from("x'");
            hex(&key[..key_len], &mut text);
            text.push('\'');
            text.into_bytes()
        }
        NativeKey::RawWithSalt { key, salt } => {
            let mut text = String::from("x'");
            hex(&key[..key_len], &mut text);
            hex(salt, &mut text);
            text.push('\'');
            text.into_bytes()
        }
        NativeKey::Passphrase { bytes, .. } => bytes.clone(),
    }
}

/// The bytes that actually determine `key`'s derived key, ignoring parts that influence only what
/// gets stored for reopening (the embedded salt in [`NativeKey::RawWithSalt`], never consulted
/// for the key itself since a raw key bypasses derivation entirely), a requested `kdf_iter` a
/// cipher's own `GenerateKey*Cipher` never reads ([`Cipher::has_kdf_iter`] false), passphrase
/// bytes beyond [`Cipher::passphrase_prefix_len`] that the same function never reads either, or
/// trailing zero bytes HMAC pads anyway ([`NativeConfig::passphrase_hmac_block`]).
fn native_key_material(key: &NativeKey, config: &NativeConfig, key_len: usize) -> Vec<u8> {
    match key {
        NativeKey::Raw(key) | NativeKey::RawWithSalt { key, .. } => key[..key_len].to_vec(),
        NativeKey::Passphrase { bytes, .. } => {
            let read = config
                .cipher
                .passphrase_prefix_len()
                .map_or(bytes.as_slice(), |limit| &bytes[..bytes.len().min(limit)]);
            match config.passphrase_hmac_block() {
                Some(block) if read.len() <= block => {
                    let end = read.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
                    read[..end].to_vec()
                }
                _ => read.to_vec(),
            }
        }
    }
}

/// Whether `a` and `b` derive the same key under `config`, so a round-trip or wrong-key oracle
/// comparing them would prove nothing.
fn native_keys_equivalent(
    a: &NativeKey,
    b: &NativeKey,
    config: &NativeConfig,
    key_len: usize,
) -> bool {
    let cipher = config.cipher;
    if native_key_material(a, config, key_len) != native_key_material(b, config, key_len) {
        return false;
    }
    match (a, b) {
        (
            NativeKey::Passphrase { kdf_iter: ia, .. },
            NativeKey::Passphrase { kdf_iter: ib, .. },
        ) => ia == ib || !cipher.has_kdf_iter(),
        // Same literal bytes, but one side bypasses derivation (a raw key) and the other goes
        // through it (a passphrase): only indistinguishable where the cipher has no raw-key
        // bypass to begin with, so every key form degenerates to a passphrase already.
        (NativeKey::Passphrase { .. }, _) | (_, NativeKey::Passphrase { .. }) => {
            !cipher.supports_raw_key()
        }
        _ => true,
    }
}

/// The AEGIS `algorithm` value for the 128-bit or 256-bit family, picking the plain (non-SIMD)
/// variant of each: `aegis-128l` or `aegis-256`. The SIMD variants share the same key length and
/// tag, so are not separately modelled.
const fn aegis_algorithm(select_256: bool) -> c_int {
    if select_256 {
        4
    } else {
        1
    }
}

/// Sets every SQLite3MC cipher parameter `config` carries, without touching the key. The
/// resulting pending state is consumed by whichever key-setup call runs next on this
/// connection: [`Connection::key`], `ATTACH ... KEY`, or [`Connection::rekey`].
fn stage_cipher(connection: &Connection, config: &NativeConfig) {
    let cipher_name = CString::new(config.cipher.name()).expect("cipher names have no NUL");
    let index = Connection::sqlite3mc_cipher_index(&cipher_name);
    assert_eq!(
        connection.sqlite3mc_config(c"cipher", index),
        index,
        "SQLite3MC refused its {} scheme",
        config.cipher.name()
    );
    let set = |param: &CStr, value: c_int| {
        let set = connection.sqlite3mc_config_cipher(&cipher_name, param, value);
        assert_eq!(
            set,
            value,
            "SQLite3MC refused {} {param:?} = {value}",
            config.cipher.name()
        );
    };
    // `legacy` first, since setting it resets the other parameters to that version's defaults.
    if config.cipher.has_legacy_param() {
        set(c"legacy", 0);
    }
    if matches!(config.cipher, Cipher::SqlCipher) {
        if let Some(algorithm) = config.kdf_algorithm {
            set(c"kdf_algorithm", sqlite3mc_algorithm(algorithm));
        }
        if let Some(algorithm) = config.hmac_algorithm {
            set(c"hmac_algorithm", sqlite3mc_algorithm(algorithm));
        }
        if let Some(hmac_use) = config.hmac_use {
            set(c"hmac_use", c_int::from(hmac_use));
        }
    }
    if matches!(config.cipher, Cipher::Aegis) {
        set(c"algorithm", aegis_algorithm(config.aegis_algorithm_256));
    }
    if let NativeKey::Passphrase { kdf_iter, .. } = config.key {
        if config.cipher.has_kdf_iter() {
            set(c"kdf_iter", c_int::from(kdf_iter));
        }
    }
    if let Some(header) = config.plaintext_header_size {
        set(c"plaintext_header_size", c_int::from(header));
    }
}

/// Applies `config` and the key to SQLite3MC's own native scheme, returning only a refused key as
/// an observation.
fn configure_native(connection: &Connection, config: &NativeConfig) -> Result<(), Code> {
    stage_cipher(connection, config);
    connection.key(&native_key_bytes(
        &config.key,
        config.cipher.key_len(config.aegis_algorithm_256),
    ))
}

/// Opens a new SQLite3MC file at `path` and applies `config`'s cipher and key, panicking with
/// `what` (e.g. `"file"`, `"main database"`) naming the file in the message if SQLite3MC refuses
/// to create or key it.
fn open_native(path: &Path, config: &NativeConfig, what: &str) -> Connection {
    let cipher = config.cipher;
    let connection = Connection::open(&c_path(path), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)
        .unwrap_or_else(|code| {
            panic!(
                "SQLite3MC cannot create a {} {what}: {code:?}",
                cipher.name()
            )
        });
    if let Err(code) = configure_native(&connection, config) {
        panic!(
            "SQLite3MC refused the key of a new {} {what}: {code:?}",
            cipher.name()
        );
    }
    connection
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

/// Runs `ops` against an already-open, already-configured connection, panicking with `label` and
/// `context`'s own Debug output naming what failed.
pub(crate) fn run_workload<D: std::fmt::Debug>(
    connection: &Connection,
    label: &str,
    ops: &[Op],
    context: &D,
) {
    let mut created = [false; 3];
    // Tables created inside a transaction disappear again on rollback.
    let mut before_transaction: Option<[bool; 3]> = None;
    let run = |text: &str, params: &[Param<'_>], op: &Op| {
        if let Err(code) = connection.execute(&sql(text), params) {
            panic!("{label} failed {op:?} ({text}) with {code:?} for {context:#?}");
        }
    };
    for op in ops.iter().take(MAX_OPS) {
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

/// Everything SQLite3MC can read from the file at `path` with the key `configure` applies, up
/// to the first failure.
fn dump(path: &Path, configure: impl FnOnce(&Connection) -> Result<(), Code>) -> Vec<Record> {
    let mut log = Vec::new();
    let connection = match Connection::open(&c_path(path), SQLITE_OPEN_READONLY) {
        Ok(connection) => connection,
        Err(code) => {
            log.push(Record::Failed("open", code));
            return log;
        }
    };
    if let Err(code) = configure(&connection) {
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

fn rows(connection: &Connection, stage: &'static str, query: &CStr, log: &mut Vec<Record>) -> Step {
    let mut statement = connection.prepare(query).map_err(|code| (stage, code))?;
    while let Some(row) = statement.next_row().map_err(|code| (stage, code))? {
        log.push(Record::Row(stage, row));
    }
    Ok(())
}

/// Logs every page's content area, cutting the reserved bytes page 1's header byte 20 names.
fn pages(connection: &Connection, log: &mut Vec<Record>) -> Step {
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
