//! What one execution does, decoded from fuzzer bytes into values both libraries accept.

use arbitrary::{Arbitrary, Result, Unstructured};

/// The library that writes the database. The other one reads it.
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// SQLCipher, the reference.
    SqlCipher,
    /// SQLite3MC's `sqlcipher` scheme.
    Sqlite3mc,
}

/// A hash both sides offer for key derivation and page authentication.
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

/// How the database is keyed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    /// A raw 32-byte key, which skips key derivation.
    Raw([u8; 32]),
    /// A raw key with an explicit 16-byte salt, which also lets page 1 keep a plaintext header.
    RawWithSalt {
        /// The key.
        key: [u8; 32],
        /// The salt.
        salt: [u8; 16],
        /// Bytes of page 1 left unencrypted, a multiple of 16 up to 96, or 0.
        plaintext_header: u8,
    },
    /// A passphrase run through PBKDF2 `kdf_iter` times.
    Passphrase {
        /// The passphrase, never empty.
        bytes: Vec<u8>,
        /// Iterations, 1 to 16.
        kdf_iter: u8,
    },
}

/// The cipher settings, as SQLCipher compatibility defaults plus optional overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// SQLCipher major version whose defaults apply, 1 to 4.
    pub compatibility: u8,
    /// Page size, a power of two from 512 to 65536, or the version's default.
    pub page_size: Option<u32>,
    /// Key derivation hash, or the version's default.
    pub kdf_algorithm: Option<Algorithm>,
    /// Page authentication hash, or the version's default.
    pub hmac_algorithm: Option<Algorithm>,
    /// Whether pages carry an HMAC, or the version's default.
    pub hmac: Option<bool>,
    /// The key.
    pub key: Key,
}

impl Config {
    /// Whether the key names a salt that SQLite3MC replaces with the file's, lacking a plaintext header.
    #[must_use]
    pub const fn explicit_salt_unused_by_sqlite3mc(&self) -> bool {
        matches!(self.key, Key::RawWithSalt { .. }) && self.plaintext_header() == 0
    }

    /// Page 1's plaintext header size in effect, which only compatibility 4 honours.
    #[must_use]
    pub const fn plaintext_header(&self) -> u8 {
        match self.key {
            Key::RawWithSalt {
                plaintext_header, ..
            } if self.compatibility == 4 => plaintext_header,
            _ => 0,
        }
    }

    /// Bytes each page reserves for the IV plus, with HMAC on, the digest padded to 16 bytes.
    #[must_use]
    pub fn reserved(&self) -> u32 {
        let hmac = self.hmac.unwrap_or(self.compatibility >= 2);
        let algorithm = self.hmac_algorithm.unwrap_or(if self.compatibility == 4 {
            Algorithm::Sha512
        } else {
            Algorithm::Sha1
        });
        let digest: u32 = match algorithm {
            Algorithm::Sha1 => 20,
            Algorithm::Sha256 => 32,
            Algorithm::Sha512 => 64,
        };
        16 + if hmac { digest.next_multiple_of(16) } else { 0 }
    }
}

impl<'a> Arbitrary<'a> for Config {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let compatibility = u.int_in_range(1..=4)?;
        let page_size = if u.arbitrary()? {
            Some(1 << u.int_in_range(9..=16)?)
        } else {
            None
        };
        let kdf_algorithm = u.arbitrary()?;
        let hmac_algorithm = u.arbitrary()?;
        let hmac = u.arbitrary()?;
        let key = match u.int_in_range(0..=2)? {
            0 => Key::Raw(u.arbitrary()?),
            1 => Key::RawWithSalt {
                key: u.arbitrary()?,
                salt: u.arbitrary()?,
                plaintext_header: 16 * u.int_in_range(0..=6)?,
            },
            _ => {
                let len = u.int_in_range(1..=64)?;
                let mut bytes = u.bytes(len)?.to_vec();
                // SQLite3MC documents `raw:` as raw key syntax for every cipher, SQLCipher has none.
                if bytes.starts_with(b"raw:") {
                    bytes[0] = b'R';
                }
                Key::Passphrase {
                    bytes,
                    kdf_iter: u.int_in_range(1..=16)?,
                }
            }
        };
        let mut config = Self {
            compatibility,
            page_size,
            kdf_algorithm,
            hmac_algorithm,
            hmac,
            key,
        };
        // `sqlite3BtreeSetPageSize` enlarges 512-byte pages to 1024 when more than 32 bytes are reserved.
        if config.page_size == Some(512) && config.reserved() > 32 {
            config.page_size = Some(1024);
        }
        Ok(config)
    }
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

/// One execution.
#[derive(Debug, Clone, PartialEq)]
pub struct Case {
    /// The library that writes the database.
    pub writer: Side,
    /// Cipher settings, identical on both sides.
    pub config: Config,
    /// Workload the writer runs, at most [`MAX_OPS`] steps of it.
    pub ops: Vec<Op>,
    /// Damage applied to a copy of the finished file, at most [`MAX_FLIPS`] flips of it.
    pub damage: Vec<Flip>,
}

/// [`Case`] as decoded, before the exclusions in [`Case::from`].
#[derive(Arbitrary)]
struct Draw {
    writer: Side,
    config: Config,
    ops: Vec<Op>,
    damage: Vec<Flip>,
}

impl From<Draw> for Case {
    fn from(draw: Draw) -> Self {
        let mut config = draw.config;
        // SQLCipher 4.19.0 cannot write 512-byte pages (upstream/sqlcipher-512-page-size.md).
        if draw.writer == Side::SqlCipher && config.page_size == Some(512) {
            config.page_size = Some(1024);
        }
        Self {
            writer: draw.writer,
            config,
            ops: draw.ops,
            damage: draw.damage,
        }
    }
}

impl<'a> Arbitrary<'a> for Case {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        Draw::arbitrary(u).map(Self::from)
    }

    fn arbitrary_take_rest(u: Unstructured<'a>) -> Result<Self> {
        Draw::arbitrary_take_rest(u).map(Self::from)
    }
}

/// Workload steps beyond this are ignored, bounding one execution's time. Shared by every input
/// model that runs a workload, not just [`Case`].
pub const MAX_OPS: usize = 64;
/// Flips beyond this are ignored. Shared the same way as [`MAX_OPS`].
pub const MAX_FLIPS: usize = 16;

/// One of SQLite3MC's native cipher schemes, every one but `sqlcipher`.
///
/// The differential fuzzer above already covers `sqlcipher` against a real second implementation.
/// These have none, so they are tested for self-consistency instead: round-trip, a wrong key never
/// succeeding, and, where the scheme actually authenticates its pages, tamper detection.
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
    /// `rc4`. `legacy` is present but fixed at `RC4_LEGACY_DEFAULT` (min equals max), no raw key
    /// (`GenerateKeyRC4Cipher` always SHA1-digests the given bytes as a passphrase), no plaintext
    /// header, no page authentication (the weakest scheme on purpose, kept for legacy databases).
    Rc4,
    /// `ascon128`. No legacy variant. Settable PBKDF2 `kdf_iter`, a raw key with an optional
    /// embedded salt, a plaintext header, a 16-byte per-page authentication tag.
    Ascon128,
    /// `aegis`. No legacy variant. Argon2id key derivation, a raw key with an optional embedded
    /// salt, a plaintext header, AEAD by design. `algorithm` picks AEGIS-128 (16-byte key) or
    /// AEGIS-256 (32-byte key).
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
            Self::Rc4 => "rc4",
            Self::Ascon128 => "ascon128",
            Self::Aegis => "aegis",
        }
    }

    /// Whether `legacy` is actually settable, as opposed to merely present but fixed, as it is
    /// for `Rc4` (`RC4_LEGACY_DEFAULT` is both its minimum and its maximum).
    #[must_use]
    pub const fn has_legacy(self) -> bool {
        matches!(self, Self::Aes128 | Self::Aes256 | Self::ChaCha20)
    }

    /// Whether `legacy_page_size` is one of this scheme's own parameters. Unlike
    /// [`Cipher::has_legacy`], `Rc4` has this even though its own `legacy` is fixed.
    #[must_use]
    pub const fn has_legacy_page_size(self) -> bool {
        matches!(
            self,
            Self::Aes128 | Self::Aes256 | Self::ChaCha20 | Self::Rc4
        )
    }

    /// Whether `kdf_iter` (PBKDF2) is actually settable. `Aes256` has the parameter but its
    /// minimum and maximum both equal `CODEC_SHA_ITER`, so it is present yet fixed; `Aegis` has
    /// its own, different, Argon2id parameters instead.
    #[must_use]
    pub const fn has_kdf_iter(self) -> bool {
        matches!(self, Self::ChaCha20 | Self::Ascon128)
    }

    /// Whether this scheme's key setup ever calls `sqlite3mcExtractRawKey`, so a raw key, with or
    /// without an embedded salt, bypasses derivation entirely. `Aes128`, `Aes256` and `Rc4` always
    /// treat whatever bytes `key()` is given as a passphrase, so a hex string drawn to look like a
    /// raw key would just be hashed as one.
    #[must_use]
    pub const fn supports_raw_key(self) -> bool {
        matches!(self, Self::ChaCha20 | Self::Ascon128 | Self::Aegis)
    }

    /// Whether `plaintext_header_size` is one of this scheme's own parameters. Every scheme that
    /// has it also has [`Cipher::supports_raw_key`], not a coincidence: a plaintext header leaves
    /// the file's own salt bytes unencrypted, so recovering the salt to rederive a passphrase key
    /// on reopen needs it supplied back explicitly, which only a raw key with an embedded salt
    /// does ([`NativeConfig::arbitrary`] only draws a plaintext header for that key form).
    #[must_use]
    pub const fn has_plaintext_header(self) -> bool {
        matches!(self, Self::ChaCha20 | Self::Ascon128 | Self::Aegis)
    }

    /// Whether this scheme authenticates its pages, so tampering is expected to be caught.
    #[must_use]
    pub const fn authenticated(self) -> bool {
        matches!(self, Self::ChaCha20 | Self::Ascon128 | Self::Aegis)
    }

    /// How many leading bytes of a passphrase this scheme's own `GenerateKey*Cipher` actually
    /// reads, when it reads fewer than the whole thing. `Aes128` and `Aes256` both pad or truncate
    /// through `sqlite3mcPadPassword`, which copies at most 32 bytes; every other scheme consumes
    /// the full password (PBKDF2, Argon2id, or a plain hash all take an explicit length).
    #[must_use]
    pub const fn passphrase_prefix_len(self) -> Option<usize> {
        match self {
            Self::Aes128 | Self::Aes256 => Some(32),
            Self::ChaCha20 | Self::Rc4 | Self::Ascon128 | Self::Aegis => None,
        }
    }

    /// The key length in bytes this scheme actually uses, `algorithm` only relevant for `Aegis`.
    #[must_use]
    pub const fn key_len(self, aegis_algorithm_256: bool) -> usize {
        match self {
            Self::Aes128 | Self::Rc4 => 16,
            Self::Aes256 | Self::ChaCha20 | Self::Ascon128 => 32,
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
/// Unlike [`Key`], the raw forms are only ever drawn for a [`Cipher`] that
/// [`Cipher::supports_raw_key`] allows, [`NativeConfig::arbitrary`] enforces it; every other
/// scheme treats whatever bytes it is given as a passphrase.
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
    /// legacy scheme when it does not.
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

/// The cipher settings for one native-scheme execution, only the fields [`Cipher`] itself supports
/// ever drawn or applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeConfig {
    /// Which scheme.
    pub cipher: Cipher,
    /// `legacy`, when [`Cipher::has_legacy`].
    pub legacy: Option<bool>,
    /// `legacy_page_size`, a power of two from 512 to 65536, when [`Cipher::has_legacy_page_size`].
    pub page_size: Option<u32>,
    /// `plaintext_header_size`, when [`Cipher::has_plaintext_header`] and the key is
    /// [`NativeKey::RawWithSalt`]. A passphrase key's salt would otherwise be lost on reopen, since
    /// a plaintext header leaves no encrypted copy of it anywhere in the file (issue #209 on
    /// `SQLite3MultipleCiphers`, which documents `cipher_salt` as the required workaround).
    pub plaintext_header_size: Option<u8>,
    /// `algorithm`, `Aegis` only: `true` picks AEGIS-256 (32-byte key), `false` AEGIS-128.
    pub aegis_algorithm_256: bool,
    /// The key.
    pub key: NativeKey,
}

impl<'a> Arbitrary<'a> for NativeConfig {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let cipher: Cipher = u.arbitrary()?;
        let legacy = cipher.has_legacy().then(|| u.arbitrary()).transpose()?;
        let page_size = if cipher.has_legacy_page_size() && u.arbitrary()? {
            Some(1 << u.int_in_range(9..=16)?)
        } else {
            None
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
            legacy,
            page_size,
            plaintext_header_size,
            aegis_algorithm_256,
            key,
        })
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
    /// meaningful, and only applied, when [`Cipher::authenticated`].
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
    /// source comments recommend only for recovering journals written before version 1.3.0, not
    /// for general use, having previously been capable of data loss after a crash.
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
pub const MAX_ATTACHED: usize = 2;
/// Rows inserted into any one database inside an [`AttachCase`] beyond this are ignored.
pub const MAX_ATTACH_ROWS: usize = 8;

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
