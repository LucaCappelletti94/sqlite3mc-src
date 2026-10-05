//! Builds `corpus/differential` by rejection sampling: draws random bytes, decodes them through
//! the real `Arbitrary` impl exactly as libFuzzer would, and keeps the first draw that lands on
//! each target parameter family, after confirming the case runs without panicking. One committed
//! seed is therefore guaranteed to decode to a genuine, already-passing case, not a hand-built one
//! the harness never actually sees bytes for. A divergence is itself interesting input, so the
//! first panicking draw per family is kept too, in place, rather than searched past.

use std::path::Path;

use sqlite3mc_src_fuzz::{
    run,
    seedgen::{run_search, DivergencePolicy, Family, Rng},
    Algorithm, Case, Key, Side,
};

const fn has_ops(case: &Case) -> bool {
    !case.ops.is_empty()
}

#[expect(
    clippy::too_many_lines,
    reason = "a flat table of Family entries, one per matcher, not control flow to split"
)]
fn families() -> &'static [Family<Case>] {
    &[
        Family {
            name: "writer-sqlcipher",
            matches: |c| c.writer == Side::SqlCipher && has_ops(c),
        },
        Family {
            name: "writer-sqlite3mc",
            matches: |c| c.writer == Side::Sqlite3mc && has_ops(c),
        },
        Family {
            name: "compat-1",
            matches: |c| c.config.compatibility == 1 && has_ops(c),
        },
        Family {
            name: "compat-2",
            matches: |c| c.config.compatibility == 2 && has_ops(c),
        },
        Family {
            name: "compat-3",
            matches: |c| c.config.compatibility == 3 && has_ops(c),
        },
        Family {
            name: "compat-4",
            matches: |c| c.config.compatibility == 4 && has_ops(c),
        },
        Family {
            name: "page-size-default",
            matches: |c| c.config.page_size.is_none() && has_ops(c),
        },
        Family {
            name: "page-size-512",
            matches: |c| c.config.page_size == Some(512) && has_ops(c),
        },
        Family {
            name: "page-size-65536",
            matches: |c| c.config.page_size == Some(65536) && has_ops(c),
        },
        Family {
            name: "kdf-default",
            matches: |c| c.config.kdf_algorithm.is_none() && has_ops(c),
        },
        Family {
            name: "kdf-sha1",
            matches: |c| c.config.kdf_algorithm == Some(Algorithm::Sha1) && has_ops(c),
        },
        Family {
            name: "kdf-sha256",
            matches: |c| c.config.kdf_algorithm == Some(Algorithm::Sha256) && has_ops(c),
        },
        Family {
            name: "kdf-sha512",
            matches: |c| c.config.kdf_algorithm == Some(Algorithm::Sha512) && has_ops(c),
        },
        Family {
            name: "hmac-default",
            matches: |c| c.config.hmac.is_none() && has_ops(c),
        },
        Family {
            name: "hmac-off",
            matches: |c| c.config.hmac == Some(false) && has_ops(c),
        },
        Family {
            name: "hmac-on",
            matches: |c| c.config.hmac == Some(true) && has_ops(c),
        },
        Family {
            name: "hmac-algorithm-sha1",
            matches: |c| c.config.hmac_algorithm == Some(Algorithm::Sha1) && has_ops(c),
        },
        Family {
            name: "hmac-algorithm-sha256",
            matches: |c| c.config.hmac_algorithm == Some(Algorithm::Sha256) && has_ops(c),
        },
        Family {
            name: "hmac-algorithm-sha512",
            matches: |c| c.config.hmac_algorithm == Some(Algorithm::Sha512) && has_ops(c),
        },
        Family {
            name: "key-raw",
            matches: |c| matches!(c.config.key, Key::Raw(_)) && has_ops(c),
        },
        Family {
            name: "key-raw-with-salt-no-header",
            matches: |c| {
                matches!(
                    c.config.key,
                    Key::RawWithSalt {
                        plaintext_header: 0,
                        ..
                    }
                ) && has_ops(c)
            },
        },
        Family {
            name: "key-raw-with-salt-and-header",
            matches: |c| {
                matches!(
                    c.config.key,
                    Key::RawWithSalt {
                        plaintext_header, ..
                    } if plaintext_header > 0
                ) && has_ops(c)
            },
        },
        Family {
            name: "key-passphrase",
            matches: |c| matches!(c.config.key, Key::Passphrase { .. }) && has_ops(c),
        },
        Family {
            name: "corruption-present",
            matches: |c| !c.damage.is_empty() && has_ops(c),
        },
        Family {
            name: "corruption-present-hmac-off",
            matches: |c| !c.damage.is_empty() && c.config.hmac == Some(false) && has_ops(c),
        },
        Family {
            name: "corruption-present-hmac-on",
            matches: |c| !c.damage.is_empty() && c.config.hmac == Some(true) && has_ops(c),
        },
        Family {
            name: "many-ops",
            matches: |c| c.ops.len() >= 20,
        },
    ]
}

fn main() {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/differential"));
    run_search(
        families(),
        Rng::new(0x9e37_79b9_7f4a_7c15),
        dir,
        6000,
        200_000,
        run,
        &DivergencePolicy::KeepFirstDraw,
    );
}
