//! Builds `corpus/rekey` the same way `gen_native_seeds` builds `corpus/native`: rejection
//! sampling through the real `Arbitrary` impl, keeping the first *clean* draw that lands on each
//! target parameter family, after confirming the case runs without panicking. A draw that panics
//! is never committed to `corpus/rekey` (it would permanently fail the replay test); the first one
//! found per family is saved to `corpus/findings/` instead, which nothing replays, and the search
//! continues past it for a clean representative of the family.

use std::{fs, path::Path};

use arbitrary::{Arbitrary, Unstructured};
use sqlite3mc_src_fuzz::{run_rekey, Cipher, RekeyAction, RekeyCase};

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
    matches: fn(&RekeyCase) -> bool,
}

const fn has_ops(case: &RekeyCase) -> bool {
    !case.ops_before.is_empty()
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

/// Searches for a draw matching `family` that runs clean, saving it to `dir`. The first draw that
/// matches but panics is saved once to `findings_dir` instead (a genuine divergence is itself
/// worth keeping, just not where the replay test would trip over it), and search continues past
/// it for a clean representative of the family.
fn search_family(
    family: &Family,
    rng: &mut Rng,
    dir: &Path,
    findings_dir: &Path,
    attempts: usize,
) -> (bool, bool) {
    let mut saved_finding = false;
    for attempt in 0..attempts {
        // Vary the buffer length so arbitrary's Vec/Option draws see different amounts of
        // entropy; too short starves ops, too long wastes most attempts on decode failures the
        // length check below already prunes.
        let len = 64 + (attempt * 37) % 12000;
        let bytes = rng.bytes(len);
        let Ok(case) = RekeyCase::arbitrary_take_rest(Unstructured::new(&bytes)) else {
            continue;
        };
        if !(family.matches)(&case) {
            continue;
        }
        let result = std::panic::catch_unwind(|| run_rekey(&case));
        let Err(payload) = result else {
            fs::write(dir.join(family.name), &bytes).expect("corpus seed is writable");
            return (true, saved_finding);
        };
        if !saved_finding {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("<non-string panic payload>");
            println!(
                "DIVERGENCE family={} case={case:#?}\n{message}",
                family.name
            );
            fs::write(findings_dir.join(format!("rekey-{}", family.name)), &bytes)
                .expect("findings directory is writable");
            saved_finding = true;
        }
    }
    (false, saved_finding)
}

fn main() {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/rekey"));
    fs::create_dir_all(dir).expect("the corpus directory can be created");
    let findings_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/findings"));
    fs::create_dir_all(findings_dir).expect("the findings directory can be created");

    let mut rng = Rng(0x4b72_656b_6579_0001);
    let attempts_per_family = 200_000usize;
    let mut saved = 0usize;
    let mut findings = 0usize;
    let families = families();

    for family in families {
        let (found, divergence) =
            search_family(family, &mut rng, dir, findings_dir, attempts_per_family);
        findings += usize::from(divergence);
        if found {
            saved += 1;
        } else {
            println!(
                "MISS family={} (no clean match in {attempts_per_family} attempts)",
                family.name
            );
        }
    }

    println!(
        "saved={saved} families={} findings={findings}",
        families.len()
    );
}
