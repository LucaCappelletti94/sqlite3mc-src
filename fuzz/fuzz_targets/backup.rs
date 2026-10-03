#![no_main]

libfuzzer_sys::fuzz_target!(
    |case: sqlite3mc_src_fuzz::BackupCase| sqlite3mc_src_fuzz::run_backup(&case)
);
