//! Builds `corpus/wal` the same way `gen_rekey_seeds` builds `corpus/rekey`: rejection sampling
//! through the real `Arbitrary` impl, keeping the first *clean* draw that lands on each target
//! parameter family. A draw that panics is never committed to `corpus/wal` (it would
//! permanently fail the replay test); the first one found per family is saved to
//! `corpus/findings/` instead, which nothing replays, and the search continues past it for a
//! clean representative.

use std::path::Path;

use sqlite3mc_src_fuzz::{
    run_wal,
    seedgen::{run_search, DivergencePolicy, Family, Rng},
    Checkpoint, Cipher, WalCase,
};

const fn has_ops(case: &WalCase) -> bool {
    !case.ops.is_empty()
}

fn families() -> &'static [Family<WalCase>] {
    &[
        Family {
            name: "cipher-aes128",
            matches: |c| c.config.cipher == Cipher::Aes128 && has_ops(c),
        },
        Family {
            name: "cipher-aes256",
            matches: |c| c.config.cipher == Cipher::Aes256 && has_ops(c),
        },
        Family {
            name: "cipher-chacha20",
            matches: |c| c.config.cipher == Cipher::ChaCha20 && has_ops(c),
        },
        Family {
            name: "cipher-sqlcipher",
            matches: |c| c.config.cipher == Cipher::SqlCipher && has_ops(c),
        },
        Family {
            name: "cipher-ascon128",
            matches: |c| c.config.cipher == Cipher::Ascon128 && has_ops(c),
        },
        Family {
            name: "cipher-aegis",
            matches: |c| c.config.cipher == Cipher::Aegis && has_ops(c),
        },
        Family {
            name: "legacy-wal-true",
            matches: |c| c.legacy_wal && has_ops(c),
        },
        Family {
            name: "legacy-wal-false",
            matches: |c| !c.legacy_wal && has_ops(c),
        },
        Family {
            name: "checkpoint-passive",
            matches: |c| c.checkpoint == Some(Checkpoint::Passive) && has_ops(c),
        },
        Family {
            name: "checkpoint-full",
            matches: |c| c.checkpoint == Some(Checkpoint::Full) && has_ops(c),
        },
        Family {
            name: "checkpoint-restart",
            matches: |c| c.checkpoint == Some(Checkpoint::Restart) && has_ops(c),
        },
        Family {
            name: "checkpoint-truncate",
            matches: |c| c.checkpoint == Some(Checkpoint::Truncate) && has_ops(c),
        },
        Family {
            name: "checkpoint-none",
            matches: |c| c.checkpoint.is_none() && has_ops(c),
        },
        Family {
            name: "wal-truncation-present",
            matches: |c| c.truncate_wal_tail > 0 && has_ops(c),
        },
        Family {
            name: "wal-truncation-absent",
            matches: |c| c.truncate_wal_tail == 0 && has_ops(c),
        },
        Family {
            name: "legacy-wal-and-truncation",
            matches: |c| c.legacy_wal && c.truncate_wal_tail > 0 && has_ops(c),
        },
        Family {
            name: "many-ops",
            matches: |c| c.ops.len() >= 10,
        },
    ]
}

fn main() {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/wal"));
    let findings_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/findings"));
    run_search(
        families(),
        Rng::new(0x5741_4c00_5741_4c01),
        dir,
        12000,
        200_000,
        run_wal,
        &DivergencePolicy::QuarantineTo {
            dir: findings_dir,
            prefix: "wal-",
        },
    );
}
