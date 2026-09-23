#!/bin/sh -e

# Moves the vendored SQLite3MC to release VERSION. The archive checksum and the SQLite version
# come from the release's SHA256SUMS, accepted only with a valid Sigstore signature from
# SQLite3MC's own release workflow.
VERSION=${1:?usage: bump.sh VERSION}
echo "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "not a release version: $VERSION" >&2; exit 1; }

cd "$(dirname "$0")"
RELEASE="https://github.com/utelle/SQLite3MultipleCiphers/releases/download/v${VERSION}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

for file in SHA256SUMS SHA256SUMS.pem SHA256SUMS.sig; do
    curl -sfL -o "$WORK/$file" "$RELEASE/sqlite3mc-${VERSION}-$file"
done
cosign verify-blob \
    --certificate "$WORK/SHA256SUMS.pem" \
    --signature "$WORK/SHA256SUMS.sig" \
    --certificate-identity-regexp '^https://github\.com/utelle/SQLite3MultipleCiphers/\.github/workflows/[^@]+@refs/heads/main$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$WORK/SHA256SUMS"

ESCAPED=$(echo "$VERSION" | sed 's/\./\\./g')
LINE=$(grep -E "^[0-9a-f]{64}  sqlite3mc-${ESCAPED}-sqlite-[0-9]+\.[0-9]+\.[0-9]+-amalgamation\.zip$" "$WORK/SHA256SUMS")
ARCHIVE_SHA256=${LINE%% *}
SQLITE_VERSION=$(echo "$LINE" | sed -E 's/.*-sqlite-([0-9.]+)-amalgamation\.zip$/\1/')

# The crate version encodes the release, so SQLite3MC X.Y.Z becomes (100X+Y).Z.0.
MAJOR=${VERSION%%.*}
REST=${VERSION#*.}
MINOR=${REST%%.*}
PATCH=${REST#*.}
CRATE_VERSION="$((MAJOR * 100 + MINOR)).${PATCH}.0+sqlite3mc-${VERSION}-sqlite-${SQLITE_VERSION}"

sed -i -E \
    -e "s/^SQLITE3MC_VERSION=\".*\"$/SQLITE3MC_VERSION=\"${VERSION}\"/" \
    -e "s/^SQLITE_VERSION=\".*\"$/SQLITE_VERSION=\"${SQLITE_VERSION}\"/" \
    -e "s/^ARCHIVE_SHA256=\".*\"$/ARCHIVE_SHA256=\"${ARCHIVE_SHA256}\"/" \
    upgrade.sh
sed -i -E \
    -e "s/^(pub const SQLITE3MC_VERSION: &str = )\".*\";$/\1\"${VERSION}\";/" \
    -e "s/^(pub const SQLITE_VERSION: &str = )\".*\";$/\1\"${SQLITE_VERSION}\";/" \
    src/lib.rs
sed -i -E "0,/^version = \".*\"$/s//version = \"${CRATE_VERSION}\"/" Cargo.toml
cargo update --quiet -p sqlite3mc-src
cargo update --quiet --manifest-path smoke/Cargo.toml -p sqlite3mc-src

./upgrade.sh
echo "Pinned SQLite3MC ${VERSION} on SQLite ${SQLITE_VERSION} as ${CRATE_VERSION}"
