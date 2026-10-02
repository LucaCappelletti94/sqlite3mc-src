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
    /// Workload the writer runs, at most [`Case::MAX_OPS`] steps of it.
    pub ops: Vec<Op>,
    /// Damage applied to a copy of the finished file, at most [`Case::MAX_FLIPS`] flips of it.
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

impl Case {
    /// Workload steps beyond this are ignored, bounding one execution's time.
    pub const MAX_OPS: usize = 64;
    /// Flips beyond this are ignored.
    pub const MAX_FLIPS: usize = 16;
}
