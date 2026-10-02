//! Replays the committed corpus against both libraries without libFuzzer.

use arbitrary::{Arbitrary, Unstructured};
use sqlite3mc_src_fuzz::{run, Case};

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
