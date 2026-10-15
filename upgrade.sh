#!/bin/sh -e

# Re-vendors the pinned release byte for byte, trusting the pinned checksum only while the release's signed SHA256SUMS lists it. bump.sh moves the pins.

SQLITE3MC_VERSION="2.6.1"
SQLITE_VERSION="3.54.0"
ARCHIVE_SHA256="3f25af603566a23c821d8e581778b5ece2a541d2435776de57b8d845c176815a"

cd "$(dirname "$0")"
. ./sigstore.sh
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fetch_signed_sums "$SQLITE3MC_VERSION" "$WORK"

ARCHIVE="sqlite3mc-${SQLITE3MC_VERSION}-sqlite-${SQLITE_VERSION}-amalgamation.zip"
grep -qxF "$ARCHIVE_SHA256  $ARCHIVE" "$WORK/SHA256SUMS" ||
    { echo "the signed SHA256SUMS does not list $ARCHIVE with $ARCHIVE_SHA256" >&2; exit 1; }
curl -sfL -o "$WORK/$ARCHIVE" "https://github.com/utelle/SQLite3MultipleCiphers/releases/download/v${SQLITE3MC_VERSION}/$ARCHIVE"
(cd "$WORK" && echo "$ARCHIVE_SHA256  $ARCHIVE" | shasum -a 256 -c -)

mkdir -p sqlite3mc
for file in sqlite3mc_amalgamation.c sqlite3mc_amalgamation.h sqlite3ext.h; do
    unzip -p "$WORK/$ARCHIVE" "$file" > "sqlite3mc/$file"
done
curl -sfL -o sqlite3mc/LICENSE "https://raw.githubusercontent.com/utelle/SQLite3MultipleCiphers/v${SQLITE3MC_VERSION}/LICENSE"
(cd sqlite3mc && shasum -a 256 sqlite3mc_amalgamation.c sqlite3mc_amalgamation.h sqlite3ext.h LICENSE > SHA256SUMS)
