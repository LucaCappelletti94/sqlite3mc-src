//! Builds `corpus/backup` the same way `gen_attach_seeds` builds `corpus/attach`: rejection
//! sampling through the real `Arbitrary` impl, keeping the first *clean* draw that lands on each
//! target parameter family. A draw that panics is never committed to `corpus/backup` (it would
//! permanently fail the replay test); the first one found per family is saved to
//! `corpus/findings/` instead, which nothing replays, and the search continues past it for a
//! clean representative.

use std::{fs, path::Path};

use arbitrary::{Arbitrary, Unstructured};
use sqlite3mc_src_fuzz::{run_backup, BackupCase, Cipher};

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
    matches: fn(&BackupCase) -> bool,
}

const fn has_content(case: &BackupCase) -> bool {
    !case.src_ops.is_empty()
}

fn families() -> &'static [Family] {
    &[
        Family {
            name: "same-cipher-matched-page-size",
            matches: |c| {
                c.src.cipher == c.dest.cipher
                    && c.src_page_size.is_some()
                    && c.dest_page_size == c.src_page_size
                    && has_content(c)
            },
        },
        Family {
            name: "same-cipher-mismatched-page-size",
            matches: |c| {
                c.src.cipher == c.dest.cipher
                    && c.src_page_size.is_some()
                    && c.dest_page_size.is_some()
                    && c.src_page_size != c.dest_page_size
                    && has_content(c)
            },
        },
        Family {
            name: "no-page-size-set",
            matches: |c| c.src_page_size.is_none() && c.dest_page_size.is_none() && has_content(c),
        },
        Family {
            name: "different-ciphers",
            matches: |c| c.src.cipher != c.dest.cipher && has_content(c),
        },
        Family {
            name: "aes256-page-size-mismatch",
            matches: |c| {
                c.src.cipher == Cipher::Aes256
                    && c.dest.cipher == Cipher::Aes256
                    && c.src_page_size.is_some()
                    && c.dest_page_size.is_some()
                    && c.src_page_size != c.dest_page_size
                    && has_content(c)
            },
        },
        Family {
            name: "destination-has-content",
            matches: |c| !c.dest_ops.is_empty() && has_content(c),
        },
        Family {
            name: "empty-source",
            matches: |c| c.src_ops.is_empty(),
        },
    ]
}

/// Searches for a draw matching `family` that runs clean, saving it to `dir`. The first draw that
/// matches but panics is saved once to `findings_dir` instead, and search continues past it for a
/// clean representative of the family.
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
        let Ok(case) = BackupCase::arbitrary_take_rest(Unstructured::new(&bytes)) else {
            continue;
        };
        if !(family.matches)(&case) {
            continue;
        }
        let result = std::panic::catch_unwind(|| run_backup(&case));
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
            fs::write(findings_dir.join(format!("backup-{}", family.name)), &bytes)
                .expect("findings directory is writable");
            saved_finding = true;
        }
    }
    (false, saved_finding)
}

fn main() {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/backup"));
    fs::create_dir_all(dir).expect("the corpus directory can be created");
    let findings_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/findings"));
    fs::create_dir_all(findings_dir).expect("the findings directory can be created");

    let mut rng = Rng(0xBACC_0000_BACC_0001);
    let attempts_per_family = 400_000usize;
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
