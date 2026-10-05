//! Builds `corpus/native` the same way `gen_seeds` builds `corpus/differential`: rejection
//! sampling through the real `Arbitrary` impl, keeping the first draw that lands on each target
//! parameter family, after confirming the case runs without panicking.

use std::path::Path;

use sqlite3mc_src_fuzz::{
    run_native,
    seedgen::{run_search, DivergencePolicy, Family, Rng},
    Cipher, NativeCase, NativeKey,
};

const fn has_ops(case: &NativeCase) -> bool {
    !case.ops.is_empty()
}

fn families() -> &'static [Family<NativeCase>] {
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
            name: "key-raw",
            matches: |c| matches!(c.config.key, NativeKey::Raw(_)) && has_ops(c),
        },
        Family {
            name: "key-raw-with-salt",
            matches: |c| matches!(c.config.key, NativeKey::RawWithSalt { .. }) && has_ops(c),
        },
        Family {
            name: "key-passphrase",
            matches: |c| matches!(c.config.key, NativeKey::Passphrase { .. }) && has_ops(c),
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
            name: "page-size-set",
            matches: |c| c.config.page_size.is_some() && has_ops(c),
        },
        Family {
            name: "aegis-256",
            matches: |c| c.config.cipher == Cipher::Aegis && c.config.aegis_algorithm_256,
        },
        Family {
            name: "aegis-128",
            matches: |c| c.config.cipher == Cipher::Aegis && !c.config.aegis_algorithm_256,
        },
        Family {
            name: "damage-present-authenticated",
            matches: |c| c.config.cipher.authenticated() && !c.damage.is_empty() && has_ops(c),
        },
        Family {
            name: "damage-present-unauthenticated",
            matches: |c| !c.config.cipher.authenticated() && !c.damage.is_empty() && has_ops(c),
        },
        Family {
            name: "many-ops",
            matches: |c| c.ops.len() >= 20,
        },
    ]
}

fn main() {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/native"));
    run_search(
        families(),
        Rng::new(0x1332_6a65_2e9c_1b4f),
        dir,
        12000,
        200_000,
        run_native,
        &DivergencePolicy::KeepFirstDraw,
    );
}
