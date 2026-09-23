#!/bin/sh -e

# Re-vendors the pinned release byte for byte. bump.sh moves the pins.

SQLITE3MC_VERSION="2.3.6"
SQLITE_VERSION="3.53.3"
ARCHIVE_SHA256="bbd0434f9456d810cd1bb8d3767985f18f6b84648f1cd9cd1db6ccfb01819da2"

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
