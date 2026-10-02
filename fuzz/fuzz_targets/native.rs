#![no_main]

libfuzzer_sys::fuzz_target!(
    |case: sqlite3mc_src_fuzz::NativeCase| sqlite3mc_src_fuzz::run_native(&case)
);
