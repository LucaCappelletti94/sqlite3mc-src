//! Replays the committed corpora, differential against both libraries, native for
//! self-consistency, rekey for its own round-trip, and WAL mode for its own crash tolerance,
//! without libFuzzer.

use arbitrary::{Arbitrary, Unstructured};
use sqlite3mc_src_fuzz::{
    run, run_native, run_rekey, run_wal, Case, NativeCase, RekeyCase, WalCase,
};

#[test]
fn committed_corpus_agrees_with_sqlcipher() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/differential");
    let mut seeds: Vec<_> = std::fs::read_dir(dir)
        .expect("the committed corpus exists")
        .map(|entry| entry.expect("the corpus is readable").path())
        .collect();
    seeds.sort();
    assert!(!seeds.is_empty(), "{dir} holds no seeds");
    for seed in seeds {
        let bytes = std::fs::read(&seed).expect("seeds are readable");
        // libFuzzer's `fuzz_target!` decodes the same way, taking the rest of the input last.
        let case = Case::arbitrary_take_rest(Unstructured::new(&bytes))
            .unwrap_or_else(|e| panic!("{} does not decode: {e}", seed.display()));
        eprintln!("{}", seed.display());
        run(&case);
    }
}

#[test]
fn committed_native_corpus_is_self_consistent() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/native");
    let mut seeds: Vec<_> = std::fs::read_dir(dir)
        .expect("the committed corpus exists")
        .map(|entry| entry.expect("the corpus is readable").path())
        .collect();
    seeds.sort();
    assert!(!seeds.is_empty(), "{dir} holds no seeds");
    for seed in seeds {
        let bytes = std::fs::read(&seed).expect("seeds are readable");
        // libFuzzer's `fuzz_target!` decodes the same way, taking the rest of the input last.
        let case = NativeCase::arbitrary_take_rest(Unstructured::new(&bytes))
            .unwrap_or_else(|e| panic!("{} does not decode: {e}", seed.display()));
        eprintln!("{}", seed.display());
        run_native(&case);
    }
}

#[test]
fn committed_rekey_corpus_round_trips() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/rekey");
    let mut seeds: Vec<_> = std::fs::read_dir(dir)
        .expect("the committed corpus exists")
        .map(|entry| entry.expect("the corpus is readable").path())
        .collect();
    seeds.sort();
    assert!(!seeds.is_empty(), "{dir} holds no seeds");
    for seed in seeds {
        let bytes = std::fs::read(&seed).expect("seeds are readable");
        // libFuzzer's `fuzz_target!` decodes the same way, taking the rest of the input last.
        let case = RekeyCase::arbitrary_take_rest(Unstructured::new(&bytes))
            .unwrap_or_else(|e| panic!("{} does not decode: {e}", seed.display()));
        eprintln!("{}", seed.display());
        run_rekey(&case);
    }
}

#[test]
fn committed_wal_corpus_tolerates_truncation() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/wal");
    let mut seeds: Vec<_> = std::fs::read_dir(dir)
        .expect("the committed corpus exists")
        .map(|entry| entry.expect("the corpus is readable").path())
        .collect();
    seeds.sort();
    assert!(!seeds.is_empty(), "{dir} holds no seeds");
    for seed in seeds {
        let bytes = std::fs::read(&seed).expect("seeds are readable");
        // libFuzzer's `fuzz_target!` decodes the same way, taking the rest of the input last.
        let case = WalCase::arbitrary_take_rest(Unstructured::new(&bytes))
            .unwrap_or_else(|e| panic!("{} does not decode: {e}", seed.display()));
        eprintln!("{}", seed.display());
        run_wal(&case);
    }
}
