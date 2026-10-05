//! Builds `corpus/backup` the same way `gen_attach_seeds` builds `corpus/attach`: rejection
//! sampling through the real `Arbitrary` impl, keeping the first *clean* draw that lands on each
//! target parameter family. A draw that panics is never committed to `corpus/backup` (it would
//! permanently fail the replay test); the first one found per family is saved to
//! `corpus/findings/` instead, which nothing replays, and the search continues past it for a
//! clean representative.

use std::path::Path;

use sqlite3mc_src_fuzz::{
    run_backup,
    seedgen::{run_search, DivergencePolicy, Family, Rng},
    BackupCase, Cipher,
};

const fn has_content(case: &BackupCase) -> bool {
    !case.src_ops.is_empty()
}

fn families() -> &'static [Family<BackupCase>] {
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

fn main() {
    let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/backup"));
    let findings_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/findings"));
    run_search(
        families(),
        Rng::new(0xBACC_0000_BACC_0001),
        dir,
        12000,
        400_000,
        run_backup,
        &DivergencePolicy::QuarantineTo {
            dir: findings_dir,
            prefix: "backup-",
        },
    );
}
