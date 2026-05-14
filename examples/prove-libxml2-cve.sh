#!/usr/bin/env bash
#
# End-to-end demo: prove CVE-2017-9047 (libxml2
# xmlSnprintfElementContent stale-len) and verify the bundle.
#
# Requirements:
#   - Cargo + the SP1 toolchain installed (https://docs.succinct.xyz/).
#   - zkpox built: `cargo build --release` at the workspace root.
#   - Internet for the Rekor anchor (or pass --no-anchor below).

set -euo pipefail

cd "$(dirname "$0")/.."

PROVE=./target/release/zkpox-prove
VERIFY=./target/release/zkpox-verify

if [[ ! -x "$PROVE" || ! -x "$VERIFY" ]]; then
    echo "binaries not built; run: cargo build --release" >&2
    exit 1
fi

TARGET=targets/03-libxml2-cve-2017-9047.c
PREDICATE=memory-safety::oob-write
WITNESS=tests/corpus/03-overflow1-crash.bin
OUT=$(mktemp -d -t zkpox-demo.XXXXXX)
BUNDLE="$OUT/bundle.cbor"

echo "== Building backend (target $TARGET, predicate $PREDICATE) =="
"$PROVE" build-target \
    --target "$TARGET" \
    --predicate "$PREDICATE" \
    --buf-size 32

echo
echo "== Proving witness (this will invoke SP1; expect minutes) =="
"$PROVE" prove \
    --target "$TARGET" \
    --predicate "$PREDICATE" \
    --buf-size 32 \
    --witness "$WITNESS" \
    --wrap groth16 \
    --no-anchor \
    --anonymous \
    --output "$BUNDLE"

echo
echo "== Verifying bundle (strict mode) =="
"$VERIFY" "$BUNDLE" --strict --target "$TARGET"

echo
echo "Bundle written to: $BUNDLE"
