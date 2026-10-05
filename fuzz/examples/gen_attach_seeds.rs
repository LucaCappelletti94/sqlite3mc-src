//! Builds `corpus/attach` the same way `gen_wal_seeds` builds `corpus/wal`: rejection sampling
//! through the real `Arbitrary` impl, keeping the first *clean* draw that lands on each target
//! parameter family. A draw that panics is never committed to `corpus/attach` (it would
//! permanently fail the replay test); the first one found per family is saved to
//! `corpus/findings/` instead, which nothing replays, and the search continues past it for a
//! clean representative.

use std::path::Path;

use sqlite3mc_src_fuzz::{
    run_attach,
    seedgen::{run_search, DivergencePolicy, Family, Rng},
    AttachCase,
};

fn families() -> &'static [Family<AttachCase>] {
    &[
        Family {
            name: "no-attached",
            matches: |c| c.attached.is_empty(),
        },
        Family {
            name: "one-attached-correct-key",
            matches: |c| c.attached.len() == 1 && c.attached[0].attach_key.is_some(),
        },
        Family {
            name: "one-attached-omitted-key",
            matches: |c| c.attached.len() == 1 && c.attached[0].attach_key.is_none(),
        },
        Family {
            name: "two-attached",
            matches: |c| c.attached.len() >= 2,
        },
        Family {
            name: "vacuum-attached",
            matches: |c| c.attached.iter().any(|a| a.vacuum),
        },
        Family {
            name: "cross-copy",
            matches: |c| c.cross_copy && !c.attached.is_empty(),
        },
        Family {
            name: "detach-reattach",
            matches: |c| c.detach_reattach && !c.attached.is_empty(),
        },
        Family {
            name: "rows-on-both-sides",
            matches: |c| {
                c.main_rows > 0 && c.attached.iter().any(|a| a.rows > 0) && !c.attached.is_empty()
            },
        },
        Family {
            name: "everything-at-once",
            matches: |c| {
                c.attached.len() >= 2
                    && c.cross_copy
                    && c.detach_reattach
                    && c.attached.iter().any(|a| a.vacuum)
            },
        },
    ]
}

fn main() {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/attach"));
    let findings_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/findings"));
    run_search(
        families(),
        Rng::new(0x4154_4143_4154_4143),
        dir,
        12000,
        200_000,
        run_attach,
        &DivergencePolicy::QuarantineTo {
            dir: findings_dir,
            prefix: "attach-",
        },
    );
}
