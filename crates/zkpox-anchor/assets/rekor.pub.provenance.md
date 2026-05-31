# Pinned Sigstore Rekor public key — provenance

`rekor.pub` in this directory is the **public Sigstore Rekor v1 log
signing key** (ECDSA P-256 / SHA-256), pinned so `zkpox-verify` can
check a bundle's Signed Entry Timestamp (SET) on the happy path
**without a hand-supplied `--rekor-pubkey` PEM**.

| Field | Value |
|---|---|
| Algorithm | ECDSA P-256, SHA-256 |
| SPKI DER sha256 | `c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d` |
| Log | `https://rekor.sigstore.dev` |
| Pinned | 2026-05-31 |

## Why a vendored pin instead of live TUF in-process

The canonical, rotation-safe source for this key is the **Sigstore TUF
root**. We deliberately do **not** resolve it in-process with the `tough`
crate: `tough` pulls `rustls` → `aws-lc-rs` → `aws-lc-sys` + a `cmake`/C
build, which would re-bloat the reproducible build image
(`scripts/reproduce/Dockerfile`) and add C-toolchain nondeterminism to
the very thing whose job is reproducibility. Instead we **pin the key**
here and ship an out-of-process verification script
(`scripts/verify-rekor-key.sh`) so the pin stays auditable against TUF.

## How to verify / refresh this pin

The pinned key MUST equal what the Sigstore TUF root distributes. To
check (or refresh after a Sigstore key rotation):

```bash
bash scripts/verify-rekor-key.sh
```

That script fetches the key the live log publishes
(`/api/v1/log/publicKey`) and, when `sigstore` (the Python
`sigstore`/`tuf` CLI) is available, cross-checks it against the TUF
target `rekor.pub`. If the fingerprints diverge from the table above,
Sigstore rotated the key: update `rekor.pub`, this provenance table, and
`REKOR_PUBKEY_SHA256` in `crates/zkpox-anchor/src/lib.rs`, then bump the
pin date.

## Override

`zkpox-verify --rekor-pubkey <PEM>` still overrides this pin (e.g. for a
self-hosted Rekor or a future rotation before the pin is refreshed).
