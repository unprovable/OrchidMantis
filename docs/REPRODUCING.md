# Reproducing a zkpox proof (Phase 2: reproducible verification)

A disclosure bundle is only as trustworthy as a third party's ability
to **independently reproduce** its cryptographic identity. This document
shows how anyone on a clean machine can:

1. Rebuild the guest from the pinned toolchain and confirm the
   verifying-key digest comes out **byte-for-byte identical** to the one
   the bundle records, and
2. Verify the wrapped groth16 proof **without** the guest ELF or the
   multi-GB SP1 proving artifacts.

The worked example is target #4 — the verbatim upstream libxml2
CVE-2017-9047 extraction.

| Identity | Value |
|---|---|
| Target source | `targets/04-libxml2-cve-2017-9047-upstream.c` |
| `target_hash` | `sha256:b7b734258247738b4187e3fdf084097564a65a18b6e48715cf4747c64c063009` |
| `verifier_key_digest` (linux/amd64) | `sha256:00a5b2cb8f8bfb4ac5c748c9145944debdc101b67f631ea4507a87af189a9bd8` |
| Predicate | `memory-safety::oob-write` |
| Buffer size | `5000` (real DTD content-model caller geometry) |

---

## Option A — Docker (recommended, hermetic)

The pinned toolchain lives in `scripts/reproduce/Dockerfile`. From the
repo root:

```bash
docker build -f scripts/reproduce/Dockerfile -t zkpox-reproduce .
docker run --rm zkpox-reproduce
```

The container's default command runs `scripts/reproduce/verify-vk.sh`,
which builds the guest, asserts the VK digest equals the pinned value,
and verifies the committed example bundle in a clean room (empty ELF
cache). Any drift exits non-zero.

This is exactly what CI runs on every push — see
`.github/workflows/reproduce.yml`.

## Option B — Native toolchain

Pins (also in `versions.txt`; `Cargo.lock` is the source of truth for
the crate set):

- **Rust** 1.85 (enforced by `rust-toolchain.toml`)
- **SP1** `sp1-sdk` / `sp1-zkvm` / `sp1-verifier` **6.2.0** (resolved by
  `Cargo.lock`)
- **cargo-prove** `v6.1.0` via `sp1up`
- **clang + lld** with the RISC-V backend (stock LLVM is multi-target;
  Debian/Ubuntu `clang` works, as does Homebrew LLVM on macOS — Apple's
  bundled clang does **not**). Override the binary with `ZKPOX_CLANG`.

```bash
# 1. SP1 toolchain
curl -L https://sp1up.succinct.xyz | bash
sp1up --version v6.1.0

# 2. Build the host binaries against the committed lockfile
cargo build --release --locked -p zkpox-prove -p zkpox-verify

# 3. Reproduce the VK + verify the bundle
bash scripts/reproduce/verify-vk.sh
```

---

## Why the VK digest is the anchor

The guest verifying key is a deterministic function of **(target source
bytes, predicate, SP1 toolchain)**. If a reviewer compiles the same
source with the same pinned toolchain and gets the same VK digest, they
have confirmed the bundle's proof is bound to *that* source — not a
paraphrase, not a different program. The `target_hash` independently
pins the source bytes; together they close the harness-to-source gap.

## The lightweight verification path

`zkpox-verify` checks a `groth16`-wrapped proof with
`sp1_verifier::Groth16Verifier`, which embeds the SP1 version's ~300 KB
verifying key. It needs:

- the bundle (`proof.bytes` + `proof.public_values`), and
- the program vkey hash — taken from `proof.sp1_vkey_hash` if present,
  else derived from `backend.verifier_key_digest` (older bundles).

It does **not** need the guest ELF or the ~6 GB proving artifacts, so a
vendor verifies in well under a second:

```bash
target/release/zkpox-verify --cache-dir "$(mktemp -d)" \
    examples/04-libxml2-cve-2017-9047-upstream/bundle.cbor
```

The empty `--cache-dir` proves no ELF is consulted. When a guest ELF
*is* cached, the verifier additionally re-derives the VK from it and
cross-checks (defence in depth) — but its absence is not fatal on the
groth16 path. The raw STARK `core` wrap still requires the ELF.

## Producing a fresh proof (heavy)

The full groth16 prove (~16M constraints, ~6 GB artifact download on
first use) is intentionally not part of the per-commit gate. Run it
manually via the `prove` workflow
(`.github/workflows/prove.yml`, `workflow_dispatch`) or locally:

```bash
zkpox-prove prove \
  --target targets/04-libxml2-cve-2017-9047-upstream.c \
  --predicate memory-safety::oob-write --buf-size 5000 \
  --witness witnesses/04-cve-2017-9047-trigger.bin \
  --wrap groth16 \
  --provenance targets/04-libxml2-cve-2017-9047-upstream.provenance.json \
  --no-anchor --output bundle.cbor
```
