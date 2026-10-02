#![no_main]

libfuzzer_sys::fuzz_target!(|case: sqlite3mc_src_fuzz::Case| sqlite3mc_src_fuzz::run(&case));
