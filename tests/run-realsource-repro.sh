#!/usr/bin/env bash
#
# Native reproduction of CVE-2017-9047 against target #4's VERBATIM
# upstream xmlSnprintfElementContent. No SP1 toolchain required — this
# is the Phase-1 target-fidelity check: prove the real function still
# overflows on the buggy path (and benign inputs don't), using the same
# `zkpox_victim` the SP1 guest links.
#
# Exit 0 = all cases matched expectations.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
target="$root/targets/04-libxml2-cve-2017-9047-upstream.c"
harness="$here/realsource/harness.c"

cc="${CC:-cc}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "compiling target (host, as the build links it) + harness ..."
# Target compiles standalone: it includes only <stddef.h> and provides
# its own freestanding strlen/strcat shims, so no libc calls remain.
"$cc" -O0 -Wall -c "$target"  -o "$tmp/target04.o"
"$cc" -O0 -Wall -c "$harness" -o "$tmp/harness.o"
"$cc" "$tmp/target04.o" "$tmp/harness.o" -o "$tmp/repro"

echo
"$tmp/repro"
