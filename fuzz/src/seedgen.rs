//! Shared rejection-sampling machinery for the `corpus/*`-seed-generator examples.
//!
//! A deterministic byte stream, a named-family search, and a `main` driver, parameterized per
//! example by its case type, `run_*` entry point, corpus directory, RNG seed, attempts budget,
//! and divergence policy.

use std::{any::Any, fmt::Debug, fs, panic, path::Path};

use arbitrary::{Arbitrary, Unstructured};

/// A cheap deterministic byte stream, xorshift64*, fast enough for millions of draws.
pub struct Rng(u64);

impl Rng {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

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
pub struct Family<C> {
    pub name: &'static str,
    pub matches: fn(&C) -> bool,
}

/// Where a draw that matches a family but panics gets saved.
///
/// `KeepFirstDraw` keeps it alongside the clean seeds themselves, in place, because a divergence
/// is itself interesting input. `QuarantineTo` saves it to a separate directory nothing replays
/// instead, so the search can keep looking for a clean representative (a panicking seed would
/// otherwise permanently fail the replay test).
pub enum DivergencePolicy<'a> {
    KeepFirstDraw,
    QuarantineTo { dir: &'a Path, prefix: &'a str },
}

fn report_divergence<C: Debug>(name: &str, case: &C, payload: &(dyn Any + Send)) {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("<non-string panic payload>");
    println!("DIVERGENCE family={name} case={case:#?}\n{message}");
}

/// Searches for a draw matching `family`, decoding `length_modulus`-bounded byte buffers through
/// `C`'s `Arbitrary` impl and running each candidate through `run`. Saves to `dir` and reports
/// whether a draw was found and whether a divergence was saved, per `policy`.
fn search_family<C>(
    family: &Family<C>,
    rng: &mut Rng,
    dir: &Path,
    length_modulus: usize,
    attempts: usize,
    run: fn(&C),
    policy: &DivergencePolicy<'_>,
) -> (bool, bool)
where
    C: for<'a> Arbitrary<'a> + Debug + std::panic::RefUnwindSafe,
{
    let mut saved_divergence = false;
    for attempt in 0..attempts {
        // Vary the buffer length so arbitrary's Vec/Option draws see different amounts of
        // entropy; too short starves ops/content, too long wastes most attempts on decode
        // failures the length check below already prunes.
        let len = 64 + (attempt * 37) % length_modulus;
        let bytes = rng.bytes(len);
        let Ok(case) = C::arbitrary_take_rest(Unstructured::new(&bytes)) else {
            continue;
        };
        if !(family.matches)(&case) {
            continue;
        }
        let result = panic::catch_unwind(|| run(&case));
        match (&result, policy) {
            (_, DivergencePolicy::KeepFirstDraw) => {
                fs::write(dir.join(family.name), &bytes).expect("corpus seed is writable");
                if let Err(payload) = &result {
                    report_divergence(family.name, &case, payload.as_ref());
                    return (true, true);
                }
                return (true, false);
            }
            (Ok(()), DivergencePolicy::QuarantineTo { .. }) => {
                fs::write(dir.join(family.name), &bytes).expect("corpus seed is writable");
                return (true, saved_divergence);
            }
            (
                Err(payload),
                DivergencePolicy::QuarantineTo {
                    dir: findings_dir,
                    prefix,
                },
            ) => {
                if !saved_divergence {
                    report_divergence(family.name, &case, payload.as_ref());
                    fs::write(
                        findings_dir.join(format!("{prefix}{}", family.name)),
                        &bytes,
                    )
                    .expect("findings directory is writable");
                    saved_divergence = true;
                }
            }
        }
    }
    (false, saved_divergence)
}

/// Searches `families` in order with one shared `rng`, printing a `MISS` line for every family
/// that found nothing and a final summary line.
///
/// # Panics
///
/// When `dir`, or `policy`'s findings directory, cannot be created.
pub fn run_search<C>(
    families: &[Family<C>],
    mut rng: Rng,
    dir: &Path,
    length_modulus: usize,
    attempts: usize,
    run: fn(&C),
    policy: &DivergencePolicy<'_>,
) where
    C: for<'a> Arbitrary<'a> + Debug + std::panic::RefUnwindSafe,
{
    fs::create_dir_all(dir).expect("the corpus directory can be created");
    let miss_suffix = match policy {
        DivergencePolicy::KeepFirstDraw => "no match",
        DivergencePolicy::QuarantineTo {
            dir: findings_dir, ..
        } => {
            fs::create_dir_all(findings_dir).expect("the findings directory can be created");
            "no clean match"
        }
    };

    let mut saved = 0usize;
    let mut divergences = 0usize;
    for family in families {
        let (found, divergence) =
            search_family(family, &mut rng, dir, length_modulus, attempts, run, policy);
        if found {
            saved += 1;
        } else {
            println!(
                "MISS family={} ({miss_suffix} in {attempts} attempts)",
                family.name
            );
        }
        divergences += usize::from(divergence);
    }

    match policy {
        DivergencePolicy::KeepFirstDraw => {
            println!(
                "saved={saved} families={} panicked={divergences}",
                families.len()
            );
        }
        DivergencePolicy::QuarantineTo { .. } => {
            println!(
                "saved={saved} families={} findings={divergences}",
                families.len()
            );
        }
    }
}
