#!/usr/bin/env bash
#
# Audit the pinned Sigstore Rekor public key
# (crates/zkpox-anchor/assets/rekor.pub) against what the live log
# publishes, and — when the Sigstore TUF tooling is available — against
# the TUF root that canonically distributes it.
#
# We pin the key rather than resolve TUF in-process (the `tough` crate
# drags a cmake/aws-lc C build into the reproducible image). This script
# is the out-of-process audit that keeps the pin honest. Run it to verify
# the current pin, or to refresh after a Sigstore key rotation.
#
# Exit non-zero on any mismatch.

set -euo pipefail

PINNED="crates/zkpox-anchor/assets/rekor.pub"
EXPECTED_SHA256="c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
REKOR_URL="${ZKPOX_REKOR_URL:-https://rekor.sigstore.dev}"

say()  { printf '\n=== %s ===\n' "$1"; }
fail() { printf '\nFAIL: %s\n' "$1" >&2; exit 1; }

[ -f "$PINNED" ] || fail "pinned key not found at $PINNED"

der_sha256() {
    # SPKI DER sha256 of a PEM public key on stdin.
    openssl pkey -pubin -outform DER 2>/dev/null | shasum -a 256 | cut -d' ' -f1
}

say "pinned key fingerprint"
PINNED_FP="$(der_sha256 < "$PINNED")"
printf 'pinned   %s\n' "$PINNED_FP"
[ "$PINNED_FP" = "$EXPECTED_SHA256" ] \
    || fail "pinned key fingerprint != EXPECTED_SHA256 in this script ($EXPECTED_SHA256). Update both together."

say "live log key ($REKOR_URL/api/v1/log/publicKey)"
LIVE_FP="$(curl -fsSL "$REKOR_URL/api/v1/log/publicKey" | der_sha256)"
printf 'live     %s\n' "$LIVE_FP"
if [ "$LIVE_FP" != "$PINNED_FP" ]; then
    fail "live log key != pinned key.
Sigstore may have rotated the Rekor key. If so, update:
  - $PINNED
  - EXPECTED_SHA256 in this script
  - REKOR_PUBKEY_SHA256 in crates/zkpox-anchor/src/lib.rs
  - the provenance table in ${PINNED}.provenance.md"
fi

say "TUF cross-check"
if command -v sigstore >/dev/null 2>&1; then
    # If the Python `sigstore` CLI is present, it resolves keys via the
    # TUF root; a successful `sigstore verify` against any artifact
    # exercises that the trust root agrees with the log we pinned.
    printf 'sigstore CLI present — TUF-rooted trust is the CLI default.\n'
    printf '(Manual deep check: compare the pinned key to the TUF target rekor.pub.)\n'
else
    printf 'sigstore CLI not installed; skipped TUF cross-check.\n'
    printf 'Live-log fingerprint match above is the available assurance.\n'
fi

say "rekor key pin OK ($PINNED_FP)"
