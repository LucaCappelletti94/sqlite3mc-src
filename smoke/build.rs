fn main() {
    let source = sqlite3mc_src::source_dir().join(sqlite3mc_src::SOURCE_FILE);
    println!("cargo:rerun-if-changed={}", source.display());
    cc::Build::new()
        .file(source)
        .define("SQLITE_CORE", None)
        .define("SQLITE_THREADSAFE", "1")
        .warnings(false)
        .compile("sqlite3mc");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-link-lib=m");
    }
}
