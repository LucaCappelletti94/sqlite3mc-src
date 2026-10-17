//! What one execution does, decoded from fuzzer bytes into values SQLite3MC accepts.

use arbitrary::{Arbitrary, Result, Unstructured};

/// A hash the `sqlcipher` scheme takes for key derivation and page authentication.
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

/// One of the three tables a workload can touch.
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    /// `t0`.
    T0,
    /// `t1`.
    T1,
    /// `t2`.
    T2,
}

impl Table {
    /// Every table, in the order the dump reads them.
    pub const ALL: [Self; 3] = [Self::T0, Self::T1, Self::T2];

    /// The table's index in [`Table::ALL`].
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::T0 => 0,
            Self::T1 => 1,
            Self::T2 => 2,
        }
    }
}

/// A column every table has.
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Column {
    /// `i INTEGER`.
    I,
    /// `r REAL`.
    R,
    /// `t TEXT`.
    T,
    /// `b BLOB`.
    B,
}

/// A value to store, with blobs generated so a few input bytes reach overflow pages.
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum Cell {
    /// `NULL`.
    Null,
    /// An integer.
    Integer(i64),
    /// A float, NaN included.
    Real(f64),
    /// Text.
    Text(String),
    /// A pseudo-random blob of `len` bytes.
    Blob {
        /// Length.
        len: u16,
        /// Generator seed.
        seed: u8,
    },
}

/// One workload step, which the harness turns into valid SQL.
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum Op {
    /// `CREATE TABLE IF NOT EXISTS`.
    Create(Table),
    /// `CREATE INDEX IF NOT EXISTS` on one column.
    Index(Table, Column),
    /// `INSERT` one row.
    Insert(Table, [Cell; 4]),
    /// `UPDATE` one column of the row with this rowid.
    Update(Table, u8, Column, Cell),
    /// `DELETE` the row with this rowid.
    Delete(Table, u8),
    /// `VACUUM`, outside a transaction.
    Vacuum,
    /// `BEGIN`, outside a transaction.
    Begin,
    /// `COMMIT`, inside a transaction.
    Commit,
    /// `ROLLBACK`, inside a transaction.
    Rollback,
}

/// Flips `mask` into the byte at `offset` modulo the file length.
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flip {
    /// Byte offset, reduced modulo the file length.
    pub offset: u32,
    /// XOR mask.
    pub mask: u8,
}

/// Workload steps beyond this are ignored, bounding one execution's time. Shared by every
/// input model that runs a workload.
pub(crate) const MAX_OPS: usize = 64;
/// Flips beyond this are ignored. Shared the same way as [`MAX_OPS`].
pub(crate) const MAX_FLIPS: usize = 16;

/// One of SQLite3MC's own cipher schemes.
///
/// Each is tested for self-consistency: round-trip, a wrong key never succeeding, and, where
/// the scheme actually authenticates its pages, tamper detection.
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// `aes128cbc`. No KDF parameter, no raw key (`GenerateKeyAES128Cipher` always pads and
    /// MD5-digests the given bytes as a passphrase), no plaintext header, no page authentication.
    Aes128,
    /// `aes256cbc`. `kdf_iter` is present but fixed at `CODEC_SHA_ITER` (min equals max), no raw
    /// key (`GenerateKeyAES256Cipher` always pads and SHA256-digests the given bytes), no
    /// plaintext header, no page authentication.
    Aes256,
    /// `chacha20`. Settable PBKDF2 `kdf_iter`, a raw key with an optional embedded salt
    /// (`sqlite3mcExtractRawKey`), a plaintext header, a 16-byte per-page authentication tag.
    ChaCha20,
    /// `sqlcipher`, SQLite3MC's own SQLCipher-compatible scheme. Settable PBKDF2 `kdf_iter`
    /// (`kdf_algorithm` picks its hash), a raw key with an optional embedded salt, a plaintext
    /// header, and, with `hmac_use` on, a page HMAC whose digest `hmac_algorithm` sizes.
    SqlCipher,
    /// `ascon128`. No `legacy` parameter. Settable PBKDF2 `kdf_iter`, a raw key with an optional
    /// embedded salt, a plaintext header, a 16-byte per-page authentication tag.
    Ascon128,
    /// `aegis`. No `legacy` parameter. Argon2id key derivation, a raw key with an optional
    /// embedded salt, a plaintext header, AEAD by design. `algorithm` picks AEGIS-128 (16-byte
    /// key) or AEGIS-256 (32-byte key).
    Aegis,
}

impl Cipher {
    /// The name `sqlite3mc_cipher_index`/`sqlite3mc_config_cipher` take.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128 => "aes128cbc",
            Self::Aes256 => "aes256cbc",
            Self::ChaCha20 => "chacha20",
            Self::SqlCipher => "sqlcipher",
            Self::Ascon128 => "ascon128",
            Self::Aegis => "aegis",
        }
    }

    /// Whether the scheme's own parameter table has `legacy`, which the harness pins to `0`
    /// so a changed upstream default never re-enables legacy encryption.
    #[must_use]
    pub const fn has_legacy_param(self) -> bool {
        matches!(
            self,
            Self::Aes128 | Self::Aes256 | Self::ChaCha20 | Self::SqlCipher
        )
    }

    /// Whether `kdf_iter` (PBKDF2) is actually settable. `Aes256` has the parameter but its
    /// minimum and maximum both equal `CODEC_SHA_ITER`, so it is present yet fixed; `Aegis` has
    /// its own, different, Argon2id parameters instead.
    #[must_use]
    pub const fn has_kdf_iter(self) -> bool {
        matches!(self, Self::ChaCha20 | Self::SqlCipher | Self::Ascon128)
    }

    /// Whether this scheme's key setup ever calls `sqlite3mcExtractRawKey`, so a raw key, with
    /// or without an embedded salt, bypasses derivation entirely. `Aes128` and `Aes256` always
    /// treat whatever bytes `key()` is given as a passphrase, so a hex string drawn to look like
    /// a raw key would just be hashed as one.
    #[must_use]
    pub const fn supports_raw_key(self) -> bool {
        matches!(
            self,
            Self::ChaCha20 | Self::SqlCipher | Self::Ascon128 | Self::Aegis
        )
    }

    /// Whether `plaintext_header_size` is one of this scheme's own parameters. Every scheme
    /// that has it also has [`Cipher::supports_raw_key`], not a coincidence: a plaintext header
    /// leaves the file's own salt bytes unencrypted, so recovering the salt to rederive a
    /// passphrase key on reopen needs it supplied back explicitly, which only a raw key with an
    /// embedded salt does ([`NativeConfig::arbitrary`] only draws a plaintext header for that
    /// key form).
    #[must_use]
    pub const fn has_plaintext_header(self) -> bool {
        matches!(
            self,
            Self::ChaCha20 | Self::SqlCipher | Self::Ascon128 | Self::Aegis
        )
    }

    /// How many leading bytes of a passphrase this scheme's own `GenerateKey*Cipher` actually
    /// reads, when it reads fewer than the whole thing. `Aes128` and `Aes256` both pad or
    /// truncate through `sqlite3mcPadPassword`, which copies at most 32 bytes; every other
    /// scheme consumes the full password (PBKDF2, Argon2id, or a plain hash all take an
    /// explicit length).
    #[must_use]
    pub const fn passphrase_prefix_len(self) -> Option<usize> {
        match self {
            Self::Aes128 | Self::Aes256 => Some(32),
            Self::ChaCha20 | Self::SqlCipher | Self::Ascon128 | Self::Aegis => None,
        }
    }

    /// The key length in bytes this scheme actually uses, `algorithm` only relevant for `Aegis`.
    #[must_use]
    pub const fn key_len(self, aegis_algorithm_256: bool) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 | Self::ChaCha20 | Self::SqlCipher | Self::Ascon128 => 32,
            Self::Aegis => {
                if aegis_algorithm_256 {
                    32
                } else {
                    16
                }
            }
        }
    }
}

/// How a native-cipher database is keyed.
///
/// The raw forms are only ever drawn for a [`Cipher`] that [`Cipher::supports_raw_key`]
/// allows, [`NativeConfig::arbitrary`] enforces it; every other scheme treats whatever bytes
/// it is given as a passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeKey {
    /// A raw key, truncated to the scheme's own key length when applied.
    Raw([u8; 32]),
    /// A raw key with an explicit 16-byte salt, truncated to the scheme's own key length.
    RawWithSalt {
        /// The key.
        key: [u8; 32],
        /// The salt.
        salt: [u8; 16],
    },
    /// A passphrase, run through this scheme's own KDF when it has one, or hashed by its fixed
    /// scheme when it does not.
    Passphrase {
        /// The passphrase, never empty.
        bytes: Vec<u8>,
        /// Iterations, 1 to 16. Ignored by a scheme with no settable `kdf_iter`.
        kdf_iter: u8,
    },
}

impl NativeKey {
    fn arbitrary_passphrase(u: &mut Unstructured<'_>) -> Result<Self> {
        let len = u.int_in_range(1..=64)?;
        Ok(Self::Passphrase {
            bytes: u.bytes(len)?.to_vec(),
            kdf_iter: u.int_in_range(1..=16)?,
        })
    }

    /// Draws a key valid for `cipher`: a raw key, with or without an embedded salt, only when
    /// [`Cipher::supports_raw_key`] allows it, a passphrase otherwise.
    fn arbitrary_for(u: &mut Unstructured<'_>, cipher: Cipher) -> Result<Self> {
        if cipher.supports_raw_key() {
            match u.int_in_range(0..=2)? {
                0 => Ok(Self::Raw(u.arbitrary()?)),
                1 => Ok(Self::RawWithSalt {
                    key: u.arbitrary()?,
                    salt: u.arbitrary()?,
                }),
                _ => Self::arbitrary_passphrase(u),
            }
        } else {
            Self::arbitrary_passphrase(u)
        }
    }
}

impl<'a> Arbitrary<'a> for NativeKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        if u.int_in_range(0..=1)? == 0 {
            Ok(Self::Raw(u.arbitrary()?))
        } else {
            Self::arbitrary_passphrase(u)
        }
    }
}

/// The cipher settings for one native-scheme execution, only the fields [`Cipher`] itself
/// supports ever drawn or applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeConfig {
    /// Which scheme.
    pub cipher: Cipher,
    /// `kdf_algorithm`, `SqlCipher` only, or the scheme's default when `None`.
    pub kdf_algorithm: Option<Algorithm>,
    /// `hmac_algorithm`, `SqlCipher` only, or the scheme's default when `None`.
    pub hmac_algorithm: Option<Algorithm>,
    /// `hmac_use`, `SqlCipher` only, or the scheme's default when `None`.
    pub hmac_use: Option<bool>,
    /// `plaintext_header_size`, when [`Cipher::has_plaintext_header`] and the key is
    /// [`NativeKey::RawWithSalt`]. A passphrase key's salt would otherwise be lost on reopen,
    /// since a plaintext header leaves no encrypted copy of it anywhere in the file (issue #209
    /// on `SQLite3MultipleCiphers`, which documents `cipher_salt` as the required workaround).
    pub plaintext_header_size: Option<u8>,
    /// `algorithm`, `Aegis` only: `true` picks AEGIS-256 (32-byte key), `false` AEGIS-128.
    pub aegis_algorithm_256: bool,
    /// The key.
    pub key: NativeKey,
}

impl<'a> Arbitrary<'a> for NativeConfig {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let cipher: Cipher = u.arbitrary()?;
        let (kdf_algorithm, hmac_algorithm, hmac_use) = if matches!(cipher, Cipher::SqlCipher) {
            (u.arbitrary()?, u.arbitrary()?, u.arbitrary()?)
        } else {
            (None, None, None)
        };
        let aegis_algorithm_256 = matches!(cipher, Cipher::Aegis) && u.arbitrary()?;
        let key = NativeKey::arbitrary_for(u, cipher)?;
        let plaintext_header_size =
            if cipher.has_plaintext_header() && matches!(key, NativeKey::RawWithSalt { .. }) {
                Some(16 * u.int_in_range(0..=6)?)
            } else {
                None
            };
        Ok(Self {
            cipher,
            kdf_algorithm,
            hmac_algorithm,
            hmac_use,
            plaintext_header_size,
            aegis_algorithm_256,
            key,
        })
    }
}

impl NativeConfig {
    /// Whether `other` lays pages out exactly like `self`, every setting but the key equal.
    #[must_use]
    pub fn same_layout(&self, other: &Self) -> bool {
        let Self {
            cipher,
            kdf_algorithm,
            hmac_algorithm,
            hmac_use,
            plaintext_header_size,
            aegis_algorithm_256,
            key: _,
        } = self;
        *cipher == other.cipher
            && *kdf_algorithm == other.kdf_algorithm
            && *hmac_algorithm == other.hmac_algorithm
            && *hmac_use == other.hmac_use
            && *plaintext_header_size == other.plaintext_header_size
            && *aegis_algorithm_256 == other.aegis_algorithm_256
    }

    /// Whether this configuration authenticates its pages, so tampering is expected to be
    /// caught. `SqlCipher` does so only while `hmac_use` holds, its own default being on.
    #[must_use]
    pub fn authenticated(&self) -> bool {
        match self.cipher {
            Cipher::Aes128 | Cipher::Aes256 => false,
            Cipher::ChaCha20 | Cipher::Ascon128 | Cipher::Aegis => true,
            Cipher::SqlCipher => self.hmac_use.unwrap_or(true),
        }
    }

    /// The block size of the HMAC a passphrase keys in this configuration's PBKDF2. HMAC pads a
    /// key no longer than its block with zeros, so passphrases that differ only in trailing zero
    /// bytes within it derive the same key.
    #[must_use]
    pub const fn passphrase_hmac_block(&self) -> Option<usize> {
        match self.cipher {
            Cipher::ChaCha20 => Some(64),
            Cipher::SqlCipher => match self.kdf_algorithm {
                Some(Algorithm::Sha1 | Algorithm::Sha256) => Some(64),
                Some(Algorithm::Sha512) | None => Some(128),
            },
            Cipher::Aes128 | Cipher::Aes256 | Cipher::Ascon128 | Cipher::Aegis => None,
        }
    }
}

/// One native-scheme execution: write, round-trip, a wrong key, and, where authenticated, damage.
#[derive(Debug, Clone, PartialEq, Arbitrary)]
pub struct NativeCase {
    /// Cipher settings.
    pub config: NativeConfig,
    /// Workload, at most [`MAX_OPS`] steps of it.
    pub ops: Vec<Op>,
    /// Damage applied to a copy of the finished file, at most [`MAX_FLIPS`] flips of it. Only
    /// meaningful, and only applied, when the configuration [`NativeConfig::authenticated`]
    /// authenticates its pages.
    pub damage: Vec<Flip>,
    /// A key to reopen with after the workload, almost certainly not the one that wrote it.
    pub wrong_key: NativeKey,
}

/// What `PRAGMA rekey` does in one execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RekeyAction {
    /// Rekey to a new key, the same cipher scheme throughout.
    ChangeKey(NativeKey),
    /// Rekey to no key at all, decrypting the database in place.
    Decrypt,
}

/// One rekey execution: write under the original key, rekey on the same connection, write more,
/// then round-trip under the result and confirm the original key no longer reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct RekeyCase {
    /// The cipher and original key.
    pub config: NativeConfig,
    /// Workload under the original key, at most [`MAX_OPS`] steps of it.
    pub ops_before: Vec<Op>,
    /// What rekey does.
    pub action: RekeyAction,
    /// Workload continuing on the same connection after rekey, at most [`MAX_OPS`] steps of it.
    pub ops_after: Vec<Op>,
}

impl<'a> Arbitrary<'a> for RekeyCase {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let config: NativeConfig = u.arbitrary()?;
        let ops_before = u.arbitrary()?;
        let action = if u.arbitrary()? {
            RekeyAction::Decrypt
        } else if config.plaintext_header_size.is_some() {
            // A plaintext header needs the new key's salt supplied explicitly too, for the same
            // reason the original key needs it: see `NativeConfig::plaintext_header_size`'s own
            // doc comment. Rekey keeps whatever plaintext header size was already configured.
            RekeyAction::ChangeKey(NativeKey::RawWithSalt {
                key: u.arbitrary()?,
                salt: u.arbitrary()?,
            })
        } else {
            RekeyAction::ChangeKey(NativeKey::arbitrary_for(u, config.cipher)?)
        };
        let ops_after = u.arbitrary()?;
        Ok(Self {
            config,
            ops_before,
            action,
            ops_after,
        })
    }
}

/// `PRAGMA wal_checkpoint` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
pub enum Checkpoint {
    Passive,
    Full,
    Restart,
    Truncate,
}

impl Checkpoint {
    /// The keyword `PRAGMA wal_checkpoint(...)` takes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Passive => "PASSIVE",
            Self::Full => "FULL",
            Self::Restart => "RESTART",
            Self::Truncate => "TRUNCATE",
        }
    }
}

/// One WAL-mode execution: write under `journal_mode=WAL`, optionally checkpoint, close,
/// optionally truncate the `-wal` file (simulating a crash mid-write), then reopen and verify.
#[derive(Debug, Clone, PartialEq, Arbitrary)]
pub struct WalCase {
    /// The cipher and key.
    pub config: NativeConfig,
    /// `mc_legacy_wal`: `true` selects the older WAL frame encryption, which the project's own
    /// source comments recommend only for recovering journals written before version 1.3.0,
    /// not for general use.
    pub legacy_wal: bool,
    /// Workload, at most [`MAX_OPS`] steps of it.
    pub ops: Vec<Op>,
    /// An optional `PRAGMA wal_checkpoint` before closing.
    pub checkpoint: Option<Checkpoint>,
    /// Bytes truncated off the end of the `-wal` file before reopening, simulating a crash
    /// mid-write. `0` means a clean close.
    pub truncate_wal_tail: u16,
}

/// Attached databases beyond this are ignored, bounding one execution's file count. Shared the
/// same way as [`MAX_OPS`].
pub(crate) const MAX_ATTACHED: usize = 2;
/// Rows inserted into any one database inside an [`AttachCase`] beyond this are ignored.
pub(crate) const MAX_ATTACH_ROWS: usize = 8;

/// One database an [`AttachCase`]'s main connection attaches alongside its own.
#[derive(Debug, Clone, PartialEq, Eq, Arbitrary)]
pub struct AttachedDb {
    /// The cipher and key this attached file is actually created and keyed with, through
    /// `ATTACH ... KEY` on first use. Verified independently after the session by reopening this
    /// exact file standalone with this exact config.
    pub written: NativeConfig,
    /// Rows inserted into this database's own table while attached, at most
    /// [`MAX_ATTACH_ROWS`].
    pub rows: u8,
    /// Cipher settings staged, and a key supplied, in the live connection's own `ATTACH ... KEY`
    /// clause, almost certainly not [`AttachedDb::written`]. `None` omits the `KEY` clause
    /// entirely, which SQLite3MC resolves by copying the main database's own current codec
    /// verbatim (`sqlite3mcCodecAttach`'s no-key branch), never consulting this field at all.
    pub attach_key: Option<NativeConfig>,
    /// `VACUUM db1`/`VACUUM db2` after inserting.
    pub vacuum: bool,
}

/// One multi-database execution: a main connection plus up to [`MAX_ATTACHED`] attached
/// databases, each with their own cipher and key.
///
/// Exercises `ATTACH`/`DETACH` and SQLite3MC's per-connection cipher staging across them.
/// Oracle: regardless of what the shared connection does to an attached database, correct key,
/// wrong key, or an inherited one, every database's own file must stay readable afterward with
/// its own true key, never corrupted by another database's session on the same connection.
#[derive(Debug, Clone, PartialEq, Eq, Arbitrary)]
pub struct AttachCase {
    /// The main connection's own cipher and key.
    pub main: NativeConfig,
    /// Rows inserted into main's own table before attaching anything, at most
    /// [`MAX_ATTACH_ROWS`].
    pub main_rows: u8,
    /// Attached databases, at most [`MAX_ATTACHED`] of them.
    pub attached: Vec<AttachedDb>,
    /// `INSERT INTO db1.t0 SELECT i FROM main.t0`, attempted once the first attached database
    /// exists, tolerated to fail when its key turned out wrong.
    pub cross_copy: bool,
    /// `DETACH db1`, then re-`ATTACH` it with its own true key, exercising a clean reattach after
    /// whatever `attached[0].attach_key` did.
    pub detach_reattach: bool,
}

/// A `PRAGMA page_size` value, a power of two from 512 to 65536, the ordinary SQLite btree
/// page size, set through SQL rather than `sqlite3mc_config_cipher`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSize(u32);

impl PageSize {
    /// The page size in bytes.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl<'a> Arbitrary<'a> for PageSize {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Ok(Self(1 << u.int_in_range(9..=16)?))
    }
}

/// One `sqlite3_backup` execution: writes a source, optionally pre-populates a destination with
/// unrelated content, then runs `sqlite3_backup_init`/`_step`/`_finish` between them.
///
/// SQLite3MC's own compatibility guard (`sqlite3mcIsBackupSupported`, called from
/// `sqlite3_backup_init`) lets pairs disagreeing on reserved bytes through, so a backup between
/// them corrupts the destination (`upstream/sqlite3mc-backup-guard-ignores-reserve.md`).
///
/// Oracle: when [`BackupCase::src`] and [`BackupCase::dest`] are laid out identically, every
/// cipher setting but the key and the `PRAGMA page_size` equal, and every step reports success,
/// the destination must reopen cleanly with its own true key. A refused pair (`backup_init`
/// returning `NULL`) is never a defect.
#[derive(Debug, Clone, PartialEq, Arbitrary)]
pub struct BackupCase {
    /// The source database's own cipher and key.
    pub src: NativeConfig,
    /// `PRAGMA page_size` for the source, set before its first write when given.
    pub src_page_size: Option<PageSize>,
    /// Workload populating the source before backup, at most [`MAX_OPS`] steps of it.
    pub src_ops: Vec<Op>,
    /// The destination database's own cipher and key, almost certainly not [`BackupCase::src`].
    pub dest: NativeConfig,
    /// `PRAGMA page_size` for the destination, set before its first write when given.
    pub dest_page_size: Option<PageSize>,
    /// Workload populating the destination before backup overwrites it, at most [`MAX_OPS`]
    /// steps of it.
    pub dest_ops: Vec<Op>,
}
