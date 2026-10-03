#![no_main]

libfuzzer_sys::fuzz_target!(
    |case: sqlite3mc_src_fuzz::AttachCase| sqlite3mc_src_fuzz::run_attach(&case)
);
