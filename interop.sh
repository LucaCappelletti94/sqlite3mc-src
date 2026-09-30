#!/bin/sh -e

# Native SQLite3MC writes a file per cipher. Each runtime named (node when none is, chrome, firefox) runs the
# Wasm tests, which read those files and print each file they write, and native reads the printed files.
# Both sides compile the sources of $INTEROP_CRATE, an unpacked .crate with smoke/ copied in, or of this checkout.
cd "$(dirname "$0")"
crate=$(cd "${INTEROP_CRATE:-.}" && pwd)
# wasm/build.rs embeds everything in $fixtures, so what Wasm hands back goes to $returned.
fixtures="$PWD/target/interop"
returned="$PWD/target/interop-wasm"
export SQLITE_WASM_RS_SOURCE_DIR="$crate/sqlite3mc"
native() {
    cargo run --release --manifest-path "$crate/smoke/Cargo.toml" --bin interop -- "$@"
}

[ $# -gt 0 ] || set -- node
native write "$fixtures"
rm -rf "$returned" && mkdir -p "$returned"
for runtime; do
    log="$returned/$runtime.log"
    # sahpool skips itself under Node, which has no OPFS.
    case $runtime in
    node)
        vfses=memvfs
        run() { wasm-pack test --node --release --test encryption --test sahpool -- --nocapture; }
        ;;
    chrome | firefox)
        vfses="memvfs opfs"
        run() { WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --headless "--$runtime" --release --test encryption --test sahpool -- --nocapture; }
        ;;
    *) echo "unknown runtime $runtime" >&2 && exit 1 ;;
    esac
    (cd wasm && run) >"$log" 2>&1 || { cat "$log" && exit 1; }
    grep -v sqlite3mc-interop-file "$log"
    # A file whose line is missing or cut short fails the native read.
    sed -n 's/^.*sqlite3mc-interop-file \([a-z0-9-]*\) \([A-Za-z0-9+/=]*\) end$/\1 \2/p' "$log" |
        while read -r name data; do
            printf '%s' "$data" | base64 -d >"$returned/$runtime-$name.db"
        done
    for vfs in $vfses; do
        native read "$returned" "$runtime-$vfs"
    done
done
