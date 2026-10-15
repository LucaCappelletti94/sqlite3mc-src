//! Builds `corpus/shared_cache` the same way `gen_backup_seeds` builds `corpus/backup`: rejection
//! sampling through the real `Arbitrary` impl, keeping the first *clean* draw that lands on each
//! target parameter family. A draw that panics is never committed to `corpus/shared_cache` (it
//! would permanently fail the replay test); the first one found per family is saved to
//! `corpus/findings/` instead, which nothing replays, and the search continues past it for a
//! clean representative.

use std::path::Path;

use sqlite3mc_src_fuzz::{
    run_shared_cache,
    seedgen::{run_search, DivergencePolicy, Family, Rng},
    SharedCacheCase, SiblingKey,
};

const fn has_content(case: &SharedCacheCase) -> bool {
    !case.main_ops.is_empty()
}

const fn shared(key: &SiblingKey) -> bool {
    matches!(key, SiblingKey::Shared)
}

fn families() -> &'static [Family<SharedCacheCase>] {
    &[
        Family {
            name: "no-siblings",
            matches: |c| c.siblings.is_empty(),
        },
        Family {
            name: "one-sibling-correct-key",
            matches: |c| c.siblings.len() == 1 && shared(&c.siblings[0].key) && has_content(c),
        },
        Family {
            name: "one-sibling-wrong-key",
            matches: |c| c.siblings.len() == 1 && !shared(&c.siblings[0].key) && has_content(c),
        },
        Family {
            name: "many-siblings",
            matches: |c| c.siblings.len() >= 2 && has_content(c),
        },
        Family {
            name: "sibling-has-ops",
            matches: |c| c.siblings.iter().any(|s| !s.ops.is_empty()) && has_content(c),
        },
        Family {
            name: "all-siblings-correct-key",
            matches: |c| {
                !c.siblings.is_empty()
                    && c.siblings.iter().all(|s| shared(&s.key))
                    && has_content(c)
            },
        },
        Family {
            name: "mixed-correct-and-wrong",
            matches: |c| {
                c.siblings.len() >= 2
                    && c.siblings.iter().any(|s| shared(&s.key))
                    && c.siblings.iter().any(|s| !shared(&s.key))
                    && has_content(c)
            },
        },
    ]
}

fn main() {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/shared_cache"));
    let findings_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/findings"));
    run_search(
        families(),
        Rng::new(0x5C00_0000_5C00_0001),
        dir,
        8000,
        60_000,
        run_shared_cache,
        &DivergencePolicy::QuarantineTo {
            dir: findings_dir,
            prefix: "shared-cache-",
        },
    );
}
