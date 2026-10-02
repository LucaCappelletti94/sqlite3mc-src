//! Builds `corpus/native` the same way `gen_seeds` builds `corpus/differential`: rejection
//! sampling through the real `Arbitrary` impl, keeping the first draw that lands on each target
//! parameter family, after confirming the case runs without panicking.

use std::{fs, path::Path};

use arbitrary::{Arbitrary, Unstructured};
use sqlite3mc_src_fuzz::{run_native, Cipher, NativeCase, NativeKey};

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
    matches: fn(&NativeCase) -> bool,
}

const fn has_ops(case: &NativeCase) -> bool {
    !case.ops.is_empty()
}

fn families() -> &'static [Family] {
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

/// Searches for one draw matching `family`, saves it to `dir`, and reports whether it found one
/// and whether that draw panicked (also worth keeping, a divergence is itself interesting input).
fn search_family(family: &Family, rng: &mut Rng, dir: &Path, attempts: usize) -> (bool, bool) {
    for attempt in 0..attempts {
        // Vary the buffer length so arbitrary's Vec/Option draws see different amounts of
        // entropy; too short starves ops and damage, too long wastes most attempts on decode
        // failures the length check below already prunes.
        let len = 64 + (attempt * 37) % 12000;
        let bytes = rng.bytes(len);
        let Ok(case) = NativeCase::arbitrary_take_rest(Unstructured::new(&bytes)) else {
            continue;
        };
        if !(family.matches)(&case) {
            continue;
        }
        let result = std::panic::catch_unwind(|| run_native(&case));
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
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/native"));
    fs::create_dir_all(dir).expect("the corpus directory can be created");

    let mut rng = Rng(0x1332_6a65_2e9c_1b4f);
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
