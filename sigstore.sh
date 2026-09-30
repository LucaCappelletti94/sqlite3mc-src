# shellcheck shell=sh
# SQLite3MC's release signing identity, sourced by bump.sh and upgrade.sh.

# Writes release $1's SHA256SUMS to $2/SHA256SUMS once it verifies as signed by SQLite3MC's own release workflow.
fetch_signed_sums() {
    release="https://github.com/utelle/SQLite3MultipleCiphers/releases/download/v$1"
    for file in SHA256SUMS SHA256SUMS.pem SHA256SUMS.sig; do
        curl -sfL -o "$2/$file" "$release/sqlite3mc-$1-$file"
    done
    cosign verify-blob \
        --certificate "$2/SHA256SUMS.pem" \
        --signature "$2/SHA256SUMS.sig" \
        --certificate-identity-regexp '^https://github\.com/utelle/SQLite3MultipleCiphers/\.github/workflows/[^@]+@refs/heads/main$' \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "$2/SHA256SUMS"
}
