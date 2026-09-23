#!/bin/sh -e

SQLITE3MC_VERSION="2.5.1"
SQLITE_VERSION="3.53.4"
ARCHIVE_SHA256="4125f8ff275ea953dabb3289331b20a0e76d4fc060f57148f4a5df3bf3b0d5e0"

cd "$(dirname "$0")"
ARCHIVE="sqlite3mc-${SQLITE3MC_VERSION}-sqlite-${SQLITE_VERSION}-amalgamation.zip"
RELEASE="https://github.com/utelle/SQLite3MultipleCiphers/releases/download/v${SQLITE3MC_VERSION}"
curl -sfL -o "$ARCHIVE" "$RELEASE/$ARCHIVE"
echo "$ARCHIVE_SHA256  $ARCHIVE" | shasum -a 256 -c -

mkdir -p sqlite3mc
for file in sqlite3mc_amalgamation.c sqlite3mc_amalgamation.h sqlite3ext.h; do
    unzip -p "$ARCHIVE" "$file" > "sqlite3mc/$file"
done
rm -f "$ARCHIVE"
curl -sfL -o sqlite3mc/LICENSE "https://raw.githubusercontent.com/utelle/SQLite3MultipleCiphers/v${SQLITE3MC_VERSION}/LICENSE"
(cd sqlite3mc && shasum -a 256 sqlite3mc_amalgamation.c sqlite3mc_amalgamation.h sqlite3ext.h LICENSE > SHA256SUMS)

echo "Now set SQLITE3MC_VERSION and SQLITE_VERSION in src/lib.rs and the version in Cargo.toml."
