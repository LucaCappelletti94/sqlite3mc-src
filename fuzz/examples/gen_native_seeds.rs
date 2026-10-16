//! Builds `corpus/native`: rejection sampling through the real `Arbitrary` impl, keeping the
//! first *clean* draw that lands on each target parameter family, after confirming the case
//! runs without panicking.

use std::path::Path;

use sqlite3mc_src_fuzz::{
    run_native,
    seedgen::{run_search, DivergencePolicy, Family, Rng},
    Algorithm, Cipher, NativeCase, NativeKey,
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
            name: "cipher-sqlcipher",
            matches: |c| c.config.cipher == Cipher::SqlCipher && has_ops(c),
        },
        Family {
            name: "cipher-ascon128",
            matches: |c| c.config.cipher == Cipher::Ascon128 && has_ops(c),
        },
        Family {
            name: "sqlcipher-sha1-damage",
            matches: |c| {
                c.config.cipher == Cipher::SqlCipher
                    && c.config.hmac_algorithm == Some(Algorithm::Sha1)
                    && !c.damage.is_empty()
                    && has_ops(c)
            },
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
            name: "sqlcipher-hmac-off",
            matches: |c| c.config.hmac_use == Some(false) && has_ops(c),
        },
        Family {
            name: "sqlcipher-hmac-sha1",
            matches: |c| c.config.hmac_algorithm == Some(Algorithm::Sha1) && has_ops(c),
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
            matches: |c| c.config.authenticated() && !c.damage.is_empty() && has_ops(c),
        },
        Family {
            name: "damage-present-unauthenticated",
            matches: |c| !c.config.authenticated() && !c.damage.is_empty() && has_ops(c),
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
