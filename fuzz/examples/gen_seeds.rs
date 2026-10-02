//! Builds `corpus/differential` by rejection sampling: draws random bytes, decodes them through
//! the real `Arbitrary` impl exactly as libFuzzer would, and keeps the first draw that lands on
//! each target parameter family, after confirming the case runs without panicking. One committed
//! seed is therefore guaranteed to decode to a genuine, already-passing case, not a hand-built one
//! the harness never actually sees bytes for.

use std::{fs, path::Path};

use arbitrary::{Arbitrary, Unstructured};
use sqlite3mc_src_fuzz::{run, Algorithm, Case, Key, Side};

/// A cheap deterministic byte stream, xorshift64*, fast enough for millions of draws.
struct Rng(u64);

impl Rng {
    const fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

/// One family to search for, named for the seed file, matched against the decoded case.
struct Family {
    name: &'static str,
    matches: fn(&Case) -> bool,
}

const fn has_ops(case: &Case) -> bool {
    !case.ops.is_empty()
}

#[expect(
    clippy::too_many_lines,
    reason = "a flat table of Family entries, one per matcher, not control flow to split"
)]
fn families() -> &'static [Family] {
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

/// Searches for one draw matching `family`, saves it to `dir`, and reports whether it found one
/// and whether that draw panicked (also worth keeping, a divergence is itself interesting input).
fn search_family(family: &Family, rng: &mut Rng, dir: &Path, attempts: usize) -> (bool, bool) {
    for attempt in 0..attempts {
        // Vary the buffer length so arbitrary's Vec/Option draws see different amounts of
        // entropy; too short starves ops and damage, too long wastes most attempts on decode
        // failures the length check below already prunes.
        let len = 64 + (attempt * 37) % 6000;
        let bytes = rng.bytes(len);
        let Ok(case) = Case::arbitrary_take_rest(Unstructured::new(&bytes)) else {
            continue;
        };
        if !(family.matches)(&case) {
            continue;
        }
        let result = std::panic::catch_unwind(|| run(&case));
        fs::write(dir.join(family.name), &bytes).expect("corpus seed is writable");
        let Err(payload) = result else {
            return (true, false);
        };
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("<non-string panic payload>");
        println!(
            "DIVERGENCE family={} case={case:#?}\n{message}",
            family.name
        );
        return (true, true);
    }
    (false, false)
}

fn main() {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/differential"));
    fs::create_dir_all(dir).expect("the corpus directory can be created");

    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let attempts_per_family = 200_000usize;
    let mut saved = 0usize;
    let mut panicked = 0usize;
    let families = families();

    for family in families {
        let (found, divergence) = search_family(family, &mut rng, dir, attempts_per_family);
        if found {
            saved += 1;
            panicked += usize::from(divergence);
        } else {
            println!(
                "MISS family={} (no match in {attempts_per_family} attempts)",
                family.name
            );
        }
    }

    println!(
        "saved={saved} families={} panicked={panicked}",
        families.len()
    );
}
