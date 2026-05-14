#!/usr/bin/env bash
#
# Verify a bundle.cbor — minimal example.
#
# Usage: verify-bundle.sh path/to/bundle.cbor [path/to/target.c]

set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <bundle.cbor> [target.c]" >&2
    exit 2
fi

BUNDLE="$1"
TARGET="${2:-}"

VERIFY=./target/release/zkpox-verify
if [[ ! -x "$VERIFY" ]]; then
    echo "verifier not built; run: cargo build --release" >&2
    exit 1
fi

if [[ -n "$TARGET" ]]; then
    "$VERIFY" "$BUNDLE" --strict --json --target "$TARGET"
else
    "$VERIFY" "$BUNDLE" --json
fi
