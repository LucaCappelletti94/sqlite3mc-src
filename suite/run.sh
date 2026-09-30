#!/bin/sh -e
# Runs SQLite3MC's own tests, a rekey of every cipher, and SQLite's TCL suite against the shipped amalgamation.

cd "$(dirname "$0")/.."
ROOT=$(pwd)
SHIPPED="$ROOT/sqlite3mc/sqlite3mc_amalgamation.c"
HEADER="$ROOT/sqlite3mc/sqlite3mc_amalgamation.h"
# shellcheck source=sigstore.sh
. "$ROOT/sigstore.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# SQLite test cases that fail by SQLite3MC's design or through a named SQLite3MC defect, each with its reason.
EXPECTED_FAILURES=$(cat <<'EOF'
mutex1.2.singlethread.4  SQLite3MC's VFS guards its open files with a recursive mutex of its own
mutex1.2.multithread.4   SQLite3MC's VFS guards its open files with a recursive mutex of its own
mutex1.3.2               a -nomutex connection still takes that process-wide VFS mutex
memsubsys2-4.1           SQLite3MC's cipher tables stay allocated between sqlite3_initialize and sqlite3_shutdown
memsubsys2-4.3           SQLite3MC's cipher tables stay allocated between sqlite3_initialize and sqlite3_shutdown
memsubsys2-4.4           SQLite3MC's cipher tables stay allocated between sqlite3_initialize and sqlite3_shutdown
memsubsys2-4.11          SQLite3MC's cipher tables stay allocated between sqlite3_initialize and sqlite3_shutdown
backup2-10               mcIoRead drops read errors of the real file, fixed by SQLite3MC pull request 272 after 2.5.1
EOF
)
# SQLite test files that crash through a named SQLite3MC defect, each with its reason.
EXPECTED_CRASHES=$(cat <<'EOF'
init       sqlite3mcRegisterCipher writes through an unchecked sqlite3_malloc when an allocation fails
quota      sqlite3mcCloneCodecParameterTable writes through an unchecked sqlite3_malloc when an allocation fails
multiplex  sqlite3mcCloneCodecParameterTable writes through an unchecked sqlite3_malloc when an allocation fails
EOF
)
# SQLite test files not run, each with its reason.
SKIP_FILES=""

# SANITIZE=1 builds under clang with AddressSanitizer and UBSan, where any report ends the process.
CC=cc
OPT="-O2"
if [ -n "${SANITIZE:-}" ]; then
    CC=clang
    OPT="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all"
    ASAN_OPTIONS="detect_leaks=1:abort_on_error=1"
    UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
    export ASAN_OPTIONS UBSAN_OPTIONS
    SKIP_FILES=$(cat <<'EOF'
crash8  its simulated crashes end child processes holding memory, which LeakSanitizer reports on SQLite alone too
EOF
)
fi

# A clean sanitizer run only counts if the binary is really instrumented.
instrumented() {
    [ -z "${SANITIZE:-}" ] || { nm "$1" | grep -q __asan_report_load && nm "$1" | grep -q __ubsan_handle; } ||
        { echo "$1 is not instrumented" >&2; exit 1; }
}

# SQLite3MC's shell from the signed release archive, over the shipped amalgamation and header.
version=$(sed -n 's/^#define SQLITE3MC_VERSION_STRING *"SQLite3 Multiple Ciphers \(.*\)"$/\1/p' "$HEADER")
sqlite_version=$(sed -n 's/^#define SQLITE_VERSION *"\(.*\)"$/\1/p' "$HEADER")
archive="sqlite3mc-${version}-sqlite-${sqlite_version}-amalgamation.zip"
fetch_signed_sums "$version" "$WORK"
curl -sfL -o "$WORK/$archive" "https://github.com/utelle/SQLite3MultipleCiphers/releases/download/v${version}/$archive"
(cd "$WORK" && grep -F "  $archive" SHA256SUMS | shasum -a 256 -c -)
unzip -q -d "$WORK" "$WORK/$archive" shell3mc_amalgamation.c
printf '#include "%s"\n' "$HEADER" > "$WORK/sqlite3.h"
# shellcheck disable=SC2086
$CC $OPT -I"$WORK" -o "$WORK/sqlite3mc" "$WORK/shell3mc_amalgamation.c" "$SHIPPED" -lm
instrumented "$WORK/sqlite3mc"

# SQLite3MC's test directory at the commit its signing certificate names, run as its own CI runs it.
commit=$(base64 -d "$WORK/SHA256SUMS.pem" | openssl x509 -noout -text |
    awk '/1\.3\.6\.1\.4\.1\.57264\.1\.3:/ { getline; gsub(/ /, ""); print }')
git init --quiet "$WORK/mc"
git -C "$WORK/mc" fetch --quiet --depth 1 https://github.com/utelle/SQLite3MultipleCiphers.git "refs/tags/v${version}:refs/tags/v${version}"
[ "$(git -C "$WORK/mc" rev-parse "v${version}^{commit}")" = "$commit" ] ||
    { echo "SQLite3MC v${version} does not point at the signed commit ${commit}" >&2; exit 1; }
git -C "$WORK/mc" archive "$commit" test | tar x -C "$WORK/mc"
failed=""
# Upstream never checks the output, so its results, without the echoed script lines, are compared here.
while read -r name db script; do
    echo "== $name"
    (cd "$WORK/mc" && "$WORK/sqlite3mc" "$db" ".read test/$script" 2>&1 | grep -vxF -f "test/$script") || true
done > "$WORK/sqlite3mc.out" <<'EOF'
test1          test1.db3                          test1.sql
test2          test2.db3                          test2.sql
test3          test/persons-aegis-testkey.db3     test3.sql
test4          test/persons-ascon128-testkey.db3  test4.sql
sqlciphertest  dummy.db3                          sqlciphertest.sql
EOF
if diff -u "$ROOT/suite/expected.txt" "$WORK/sqlite3mc.out"; then echo "pass  SQLite3MC's tests"; else failed=" sqlite3mc"; fi

# Every built-in cipher encrypts, rekeys, refuses the old key and no key, and decrypts back to plaintext.
rows="WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 1000)
    INSERT INTO t SELECT x, printf('%.100c', char(65 + x % 26)) FROM n"
check="SELECT count(*), sum(a), sum(length(b)) FROM t"
mc() { "$WORK/sqlite3mc" "$db" "$@"; }
for cipher in aes128cbc aes256cbc chacha20 sqlcipher rc4 ascon128 aegis; do
    db="$WORK/rekey-$cipher.db"
    {
        mc "PRAGMA cipher='$cipher'" "PRAGMA key='before'" "CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT)" "$rows" "PRAGMA rekey='after'"
        mc "PRAGMA cipher='$cipher'" "PRAGMA key='after'" "$check" "PRAGMA integrity_check"
        mc "PRAGMA cipher='$cipher'" "PRAGMA key='before'" "$check"
        mc "$check"
        mc "PRAGMA cipher='$cipher'" "PRAGMA key='after'" "PRAGMA rekey=''"
        mc "$check" "PRAGMA integrity_check"
    } > "$WORK/rekey.out" 2> "$WORK/rekey.err" || true
    # Each invocation writes its error before its buffered results, so the two streams are compared apart.
    echo "-- errors" >> "$WORK/rekey.out"
    cat "$WORK/rekey.err" >> "$WORK/rekey.out"
    cat > "$WORK/rekey.want" <<EOF
$cipher
ok
ok
$cipher
ok
1000|500500|100000
ok
$cipher
ok
$cipher
ok
ok
1000|500500|100000
ok
-- errors
Parse error in 4th command line argument: file is not a database (26)
Parse error in 2nd command line argument: file is not a database (26)
EOF
    if diff -u "$WORK/rekey.want" "$WORK/rekey.out"; then echo "pass  rekey $cipher"; else failed="$failed rekey-$cipher"; fi
done

# SQLite's testfixture, over the SQLite sources of the check-in the amalgamation names, which the archive's
# manifest must hash to, with every file hashing to its manifest entry.
source_id=$(sed -n 's/^#define SQLITE_SOURCE_ID *"\(.*\)"$/\1/p' "$HEADER")
number=$(echo "$sqlite_version" | awk -F. '{ printf "%d%02d%02d00", $1, $2, $3 }')
curl -sfL -o "$WORK/sqlite-src.zip" "https://sqlite.org/${source_id%%-*}/sqlite-src-${number}.zip"
unzip -q "$WORK/sqlite-src.zip" -d "$WORK"
cd "$WORK/sqlite-src-${number}"
if [ "$(tail -n 1 manifest)" != "# Remove this line to create a well-formed Fossil manifest." ] ||
    [ "$(sed '$d' manifest | openssl dgst -sha3-256 -r | cut -d' ' -f1)" != "${source_id##* }" ]; then
    echo "SQLite's manifest is not check-in ${source_id##* }" >&2
    exit 1
fi
# Fossil names older files by SHA1 and newer ones by SHA3-256.
{
    awk '$1 == "F" && length($3) == 40 { print $2 }' manifest | xargs openssl dgst -sha1 -r
    awk '$1 == "F" && length($3) == 64 { print $2 }' manifest | xargs openssl dgst -sha3-256 -r
    find . -type f ! -name 'manifest*' | sed 's|^\./|file |'
} | sort > "$WORK/tree"
awk '$1 == "F" { print $3 " *" $2; print "file " $2 }' manifest | sort | cmp -s - "$WORK/tree" ||
    { echo "SQLite's source tree differs from its manifest" >&2; exit 1; }
# TCL_LIB names the tclConfig.sh directory when configure cannot find it.
CC="$CC" ./configure ${TCL_LIB:+--with-tcl="$TCL_LIB"} > configure.log
make sqlite3.c > make.log
# testfixture reaches SQLite internals through -DSQLITE_PRIVATE="", which the shipped amalgamation rejects by
# defining sqlite3mcCodecAttach static against its SQLITE_PRIVATE declaration. The copy drops that one static,
# as SQLite3MC pull request 276 proposes, and the run stops once a release no longer carries it.
line=$(grep -n -x 'sqlite3mcCodecAttach(sqlite3\* db, int nDb, const char\* zPath, const void\* zKey, int nKey)' "$SHIPPED" | cut -d: -f1)
if [ -z "$line" ] || [ "$(sed -n "$((line - 1))p" "$SHIPPED")" != "static int" ]; then
    echo "sqlite3mcCodecAttach is no longer defined static, so drop its edit from suite/run.sh" >&2
    exit 1
fi
sed "$((line - 1))s/^static int$/SQLITE_PRIVATE int/" "$SHIPPED" > sqlite3.c
[ "$(diff "$SHIPPED" sqlite3.c | grep -c '^[<>]')" -eq 2 ] || { echo "the testfixture copy differs by more than one line" >&2; exit 1; }
make testfixture CC="$CC" CFLAGS="$OPT" LDFLAGS="${SANITIZE:+$OPT}" > testfixture.log 2>&1
instrumented testfixture
printf 'sqlite3 db :memory:\nputs [db one {SELECT sqlite3mc_version()}]\n' > probe.tcl
# A testfixture that cannot open a database runs no test, so its own report ends the run.
tested=$(./testfixture probe.tcl) || { echo "Failed:$failed testfixture" >&2; exit 1; }
echo "Testing $tested with SQLite's veryquick suite"

skips=$(echo "$SKIP_FILES" | awk 'NF { printf " ~%s.test", $1 }')
# shellcheck disable=SC2086
./testfixture test/testrunner.tcl veryquick --jobs "$(nproc)" $skips > testrunner.out 2>&1 ||
    { tail -n 40 testrunner.out; echo "Failed:$failed testrunner" >&2; exit 1; }
for name in $(echo "$SKIP_FILES" | awk '{ print $1 }'); do echo "skip  $name"; done
awk -v failures="$(echo "$EXPECTED_FAILURES" | awk '{ print $1 }')" \
    -v crashes="$(echo "$EXPECTED_CRASHES" | awk '{ print $1 }')" \
    -f "$ROOT/suite/verdict.awk" testrunner.log testrunner.log || failed="$failed sqlite"

[ -z "$failed" ] || { echo "Failed:$failed" >&2; exit 1; }
