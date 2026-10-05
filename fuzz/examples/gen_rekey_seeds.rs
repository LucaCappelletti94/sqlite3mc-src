//! Builds `corpus/rekey` the same way `gen_native_seeds` builds `corpus/native`: rejection
//! sampling through the real `Arbitrary` impl, keeping the first *clean* draw that lands on each
//! target parameter family, after confirming the case runs without panicking. A draw that panics
//! is never committed to `corpus/rekey` (it would permanently fail the replay test); the first one
//! found per family is saved to `corpus/findings/` instead, which nothing replays, and the search
//! continues past it for a clean representative of the family.

use std::path::Path;

use sqlite3mc_src_fuzz::{
    run_rekey,
    seedgen::{run_search, DivergencePolicy, Family, Rng},
    Cipher, RekeyAction, RekeyCase,
};

const fn has_ops(case: &RekeyCase) -> bool {
    !case.ops_before.is_empty()
}

fn families() -> &'static [Family<RekeyCase>] {
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
            name: "cipher-rc4",
            matches: |c| c.config.cipher == Cipher::Rc4 && has_ops(c),
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
            name: "change-key",
            matches: |c| matches!(c.action, RekeyAction::ChangeKey(_)) && has_ops(c),
        },
        Family {
            name: "decrypt",
            matches: |c| matches!(c.action, RekeyAction::Decrypt) && has_ops(c),
        },
        Family {
            name: "ops-after-present",
            matches: |c| !c.ops_after.is_empty() && has_ops(c),
        },
        Family {
            name: "ops-after-empty",
            matches: |c| c.ops_after.is_empty() && has_ops(c),
        },
        Family {
            name: "plaintext-header-present",
            matches: |c| c.config.plaintext_header_size.is_some_and(|n| n > 0) && has_ops(c),
        },
        Family {
            name: "legacy-set",
            matches: |c| c.config.legacy.is_some() && has_ops(c),
        },
        Family {
            name: "many-ops-before",
            matches: |c| c.ops_before.len() >= 10,
        },
    ]
}

fn main() {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/rekey"));
    let findings_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/findings"));
    run_search(
        families(),
        Rng::new(0x4b72_656b_6579_0001),
        dir,
        12000,
        200_000,
        run_rekey,
        &DivergencePolicy::QuarantineTo {
            dir: findings_dir,
            prefix: "rekey-",
        },
    );
}
