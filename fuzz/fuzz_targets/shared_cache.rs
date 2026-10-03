#![no_main]

libfuzzer_sys::fuzz_target!(|case: sqlite3mc_src_fuzz::SharedCacheCase| {
    sqlite3mc_src_fuzz::run_shared_cache(&case);
});
