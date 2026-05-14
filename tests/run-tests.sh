#!/usr/bin/env bash
#
# zkpox regression sweep against the lifted RAPTOR witness corpus.
#
# Usage:
#   tests/run-tests.sh                       # execute-mode, full corpus
#   tests/run-tests.sh --prove               # prove-mode (slow)
#   tests/run-tests.sh --ci-subset           # CI subset, ~4 witnesses
#   tests/run-tests.sh --binary path/to/zkpox-prove

set -uo pipefail
cd "$(dirname "$0")"

MODE="--execute"   # reserved for a future --execute-mode prover flag
PROVE=0
CI_SUBSET=0
BIN="../target/release/zkpox-prove"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prove) PROVE=1; shift ;;
    --ci-subset) CI_SUBSET=1; shift ;;
    --binary) BIN="$2"; shift 2 ;;
    -h|--help) sed -n '2,/^$/p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ ! -x "$BIN" ]]; then
  echo "prover not built: $BIN" >&2
  echo "build it with: cargo build --release" >&2
  exit 2
fi

pass=0
fail=0
declare -a failures=()

# Each witness's filename encodes (target_id, kind):
#
#   NN-<name>-benign.bin   crash_only=false  AND  oob=false
#   NN-<name>-crash.bin    crash_only=true   AND  oob=true
#   NN-<name>-fn.bin       crash_only=false  AND  oob=true
#                          (canarymatch — uniform canary blind to
#                           it, position-varying gadget catches it)

# Target → buf_size + source file mapping.
target_for_witness() {
  local witness="$1"
  case "$witness" in
    01-*) echo "01-stack-bof.c 16" ;;
    02-*) echo "02-off-by-one.c 16" ;;
    03-*) echo "03-libxml2-cve-2017-9047.c 32" ;;
    *)    echo "" ;;
  esac
}

if (( CI_SUBSET )); then
  witness_set=(corpus/01-overflow1-crash.bin
               corpus/01-canarymatch-deep-fn.bin
               corpus/02-overflow1-crash.bin
               corpus/03-overflow1-crash.bin)
else
  witness_set=(corpus/*.bin)
fi

# We don't have a `--execute` flag in zkpox-prove (yet). For
# regression purposes against this corpus we'd want one. Without
# the SP1 toolchain, this script's job is documenting the intent:
# `prove` mode is the only path implemented in v0.1.

if [[ "$PROVE" -eq 0 ]]; then
  echo "NOTE: zkpox-prove v0.1 has no --execute flag; this script's --prove option is the default behaviour." >&2
fi

for w in "${witness_set[@]}"; do
  read -r src bufsize <<<"$(target_for_witness "$(basename "$w")")"
  if [[ -z "$src" ]]; then
    echo "[skip] $w — no matching target file" >&2
    continue
  fi
  printf '[testing] %s (target=%s buf=%s)... ' "$w" "$src" "$bufsize"

  # The actual SP1-bound proof for one witness takes seconds-to-
  # minutes; this script's purpose is the corpus walk, not a
  # single-witness benchmark. We rely on the prover to refuse a
  # bundle when vuln_flag is false (benign witnesses), so a clean
  # pass means crashing witnesses got bundles AND benign witnesses
  # got refused.
  expect_crash=0
  case "$w" in
    *-crash.bin|*-fn.bin) expect_crash=1 ;;
  esac

  out=$(mktemp -d -t zkpox-test.XXXXXX)
  tmp_bundle="$out/bundle.cbor"

  set +e
  "$BIN" prove \
    --target "../targets/$src" \
    --predicate memory-safety::oob-write \
    --buf-size "$bufsize" \
    --witness "$w" \
    --no-anchor --anonymous \
    --wrap core \
    --output "$tmp_bundle" \
    >/dev/null 2>&1
  rc=$?
  set -e

  rm -rf "$out"

  if (( expect_crash )); then
    if (( rc == 0 )); then
      echo "ok"; pass=$((pass+1))
    else
      echo "FAIL (expected bundle for crashing witness)"; fail=$((fail+1))
      failures+=("$w")
    fi
  else
    if (( rc != 0 )); then
      echo "ok (refused benign)"; pass=$((pass+1))
    else
      echo "FAIL (bundled a benign witness)"; fail=$((fail+1))
      failures+=("$w")
    fi
  fi
done

echo
echo "=========================="
echo "$pass passed, $fail failed"
if (( fail > 0 )); then
  for f in "${failures[@]}"; do echo "  - $f"; done
  exit 1
fi
