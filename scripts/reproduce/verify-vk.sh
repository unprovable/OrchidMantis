#!/usr/bin/env bash
#
# Reproduce the guest verifying-key digest and verify the committed
# example bundle. This is the executable form of the Phase-2
# "reproducible verification" claim: on a clean machine with the pinned
# toolchain, the VK digest must come out byte-for-byte equal to the one
# the disclosure bundle records, and the bundle must verify.
#
# Used both as the Docker image's default CMD and by the GitHub Actions
# `reproduce` workflow. Exit non-zero on any mismatch.
#
# Override the binaries / paths via env if needed (CI sets none of these
# and relies on the defaults):
#   ZKPOX_PROVE   path to zkpox-prove   (default: target/release/zkpox-prove)
#   ZKPOX_VERIFY  path to zkpox-verify  (default: target/release/zkpox-verify)

set -euo pipefail

# --- Pinned expected values (the artifact identity under review) ------
# These are the (target source, predicate, toolchain) -> VK binding for
# target #4 (libxml2 CVE-2017-9047, verbatim upstream, buf_size 5000).
# A change here means the toolchain or the target source moved; that is
# exactly what this job exists to catch.
EXPECTED_VK="00d4d1bc687843ea6828abf6a0b71377b6c27895ac2cabf1efa1b0e4b727e982"
EXPECTED_TARGET_HASH="b7b734258247738b4187e3fdf084097564a65a18b6e48715cf4747c64c063009"

TARGET_C="targets/04-libxml2-cve-2017-9047-upstream.c"
PREDICATE="memory-safety::oob-write"
BUF_SIZE=5000
EXAMPLE_BUNDLE="examples/04-libxml2-cve-2017-9047-upstream/bundle.cbor"

ZKPOX_PROVE="${ZKPOX_PROVE:-target/release/zkpox-prove}"
ZKPOX_VERIFY="${ZKPOX_VERIFY:-target/release/zkpox-verify}"

say() { printf '\n=== %s ===\n' "$1"; }
fail() { printf '\nFAIL: %s\n' "$1" >&2; exit 1; }

[ -x "$ZKPOX_PROVE" ]  || fail "zkpox-prove not found/executable at $ZKPOX_PROVE"
[ -x "$ZKPOX_VERIFY" ] || fail "zkpox-verify not found/executable at $ZKPOX_VERIFY"
[ -f "$TARGET_C" ]     || fail "target source missing: $TARGET_C"

# --- 1. Build the guest, capture the JSON report ----------------------
say "build-target (reproducing guest ELF + VK)"
BUILD_JSON="$("$ZKPOX_PROVE" build-target \
    --target "$TARGET_C" \
    --predicate "$PREDICATE" \
    --buf-size "$BUF_SIZE" \
    --json)"
printf '%s\n' "$BUILD_JSON"

# Extract bare hex values from the JSON without a jq dependency.
extract() { printf '%s' "$BUILD_JSON" | grep -o "\"$1\": *\"[0-9a-fA-F]*\"" | grep -o '[0-9a-fA-F]\{64\}' | head -1; }
GOT_VK="$(extract vk_digest || true)"
GOT_TH="$(extract target_hash || true)"

# --- 2. Assert the VK + target hash match the pinned identity ---------
say "asserting reproducibility"
[ -n "$GOT_VK" ] || fail "could not parse vk_digest from build-target --json output"
[ -n "$GOT_TH" ] || fail "could not parse target_hash from build-target --json output"

if [ "$GOT_VK" != "$EXPECTED_VK" ]; then
    fail "VK digest mismatch:
  expected $EXPECTED_VK
  got      $GOT_VK
The toolchain or the target source has drifted from the pinned identity."
fi
if [ "$GOT_TH" != "$EXPECTED_TARGET_HASH" ]; then
    fail "target_hash mismatch:
  expected $EXPECTED_TARGET_HASH
  got      $GOT_TH
The target C source bytes changed."
fi
printf 'OK: VK digest reproduced byte-for-byte (%s)\n' "$GOT_VK"
printf 'OK: target hash matches (%s)\n' "$GOT_TH"

# --- 3. Verify the committed example bundle ---------------------------
# This exercises the lightweight groth16 path. We point --cache-dir at a
# throwaway empty dir so the verify does NOT lean on the ELF we just
# built — proving a vendor with only the bundle + binaries can verify.
if [ -f "$EXAMPLE_BUNDLE" ]; then
    say "verifying committed example bundle (clean-room: no ELF cache)"
    EMPTY_CACHE="$(mktemp -d)"
    trap 'rm -rf "$EMPTY_CACHE"' EXIT
    "$ZKPOX_VERIFY" --cache-dir "$EMPTY_CACHE" "$EXAMPLE_BUNDLE" \
        || fail "verification of $EXAMPLE_BUNDLE failed"
    printf 'OK: %s verified via lightweight groth16 path\n' "$EXAMPLE_BUNDLE"
else
    printf 'NOTE: %s not present; skipping bundle verification step.\n' "$EXAMPLE_BUNDLE"
fi

say "reproducibility check PASSED"
