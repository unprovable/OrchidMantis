# SCOPE — what zkpox proves, what it does NOT prove, what you trust

Written for engineers and security reviewers who are not cryptographers.
**Read this first.** If the README, the predicate library catalogue, or any
slash-command output ever claims more than this document, treat the
discrepancy as a wrapper bug, not a doc bug.

> **Status: pre-1.0, experimental by default.** Bundles are minted with
> `experimental = true`; `zkpox-verify` banners them and, under `--cvd`
> (the disclosure-grade gate), refuses them. The `zkpox-2.0` wire format
> is frozen and regression-tested (`BUNDLE-FORMAT.md`), so the v1.0
> cutover is a deliberate `--experimental=false` re-mint, not a format
> change.

This file is adapted from RAPTOR PR #470's `docs/zkpox-scope.md`. The shape
of the scope claim is the same — only the implementation details below have
shifted now that the placeholder hashes are real bindings and the verifier
performs SP1 STARK + Rekor inclusion verification end-to-end.

---

## What zkpox proves

For each (target program, predicate) pair, a bundle produced by
`zkpox-prove` establishes exactly this statement and no more:

> Under SP1's STARK verifier — for the specific guest ELF whose
> verifying-key digest is `bundle.backend.verifier_key_digest`, and
> whose linked-in target C source hashes to `bundle.target.hash` —
> there exists a witness `w` such that the guest, invoked with `w`,
> committed public values `(target_hash, predicate_id, predicate_version,
> backend_id, backend_version, inv_flag, vuln_flag, outputs_bytes)`
> in which `inv_flag == false` (the execution itself was valid) and
> `vuln_flag == true` (the predicate observed its violation).

In plain English: **"a specific input to a specific function causes a
specific predicate to fire."**

For the two predicates that ship in v0.1, the predicate-firing condition
translates to:

| Predicate | Statement it firing implies |
|---|---|
| `crash-only` | At least one byte of the uniform-`0xA5` redzone around `buf` was overwritten with a non-`0xA5` value during the call. |
| `memory-safety::oob-write` | At least one byte outside `[buf, buf+buf_size)` was overwritten with a value that did not match the position-varying expected pattern `0xA5 XOR ((p * 0x9E37_79B1) >> 24)`. `outputs.count` is the number of such bytes; `outputs.first_offset` is the signed offset of the first one. |

A verifier learns exactly those numbers, plus the bundle's plaintext
metadata. The witness `w` itself is **not** disclosed by the proof; it
travels separately, sealed in the vendor envelope (decryptable now by the
vendor, after `T` by anyone) if and only if the producer chose to ship one.

---

## What zkpox does NOT prove

A reviewer dropping in cold may assume a "proof of exploit" establishes
some of the things below. None of them are claimed by v0.1:

- **Control-flow hijack.** The OOB-write predicate proves a write past the
  buffer end. It does **not** prove the bytes written are attacker-
  controlled, that they land on a return address or function pointer, or
  that the resulting control transfer is exploitable under ASLR / CET /
  CFG / stack canaries / RELRO.
- **Code execution / RCE.** Out of scope for v0.1. Future predicates
  (`memory-safety::indirect-call`, `cfi-bypass`) would prove this; none
  are implemented.
- **Information leak with attacker-chosen target.** The redzone primitive
  is write-detection only. Reading past `buf` doesn't trip it.
- **Exploit reliability.** The proof says "this input produced an
  OOB write *on this run inside the SP1 zkVM*." It does not characterise
  how that result varies with allocator state, kernel version,
  compiler flags, or mitigation stacks.
- **Anything about the vulnerability *class* you think you're proving.**
  Whether a redzone-violating bug is a stack BOF, a heap BOF, an
  off-by-one, or a stale-len strcat is a *labelling* convention applied
  by the producer to the bundle's metadata. The proof itself is
  class-agnostic; the predicate sees only "did the redzone change."

If your disclosure pipeline needs any of the above, **v0.1 is not yet
the right tool**. Track `docs/ROADMAP.md` for when it becomes one.

---

## What you trust when you trust a bundle

Every assurance a bundle gives you depends on at least one of these
parties being honest and at least one of these cryptographic primitives
holding. None of these dependencies are unique to zkpox — they are the
same surface any disclosure-and-anchoring pipeline lives on — but they
deserve to be enumerated.

### SP1 (the zkVM that produces the proof)

You trust that the SP1 prover's STARK is sound: a verifying proof
implies the guest program produced the committed public values from
**some** witness. SP1 is audited by Veridise, Cantina, Zellic, and
KALOS for the v6 release pinned in `versions.txt`. A soundness bug in
SP1 itself would invalidate every bundle ever produced; that is the
largest single risk in the trust chain. Subscribe to Succinct's
security advisories and pin the SP1 version in your verifier as well
as your prover.

### The compiled guest binary

You trust that the guest ELF the verifier uses to derive
`backend.verifier_key_digest` is the same one the prover used. The
verifier re-builds (or loads from cache) the guest from the published
target source + predicate selection and asserts the SP1-derived VK
digest equals what the bundle claims. As long as you trust the source
tree you built from, this binding is tight.

### The target source

You trust that `bundle.target.hash` is a faithful sha256 of the C
program you care about. Verify locally by passing
`zkpox-verify --target path/to/source.c`; the verifier re-hashes and
asserts the match. The `target.source_url` field is informational; do
not skip the local re-hash on its basis.

### age (vendor envelope path)

You trust age's X25519+ChaCha20-Poly1305 construction, and you trust
that the vendor's published age public key actually belongs to them.
The latter is a *registry* problem; v0.1 does not solve it. Pass
`--vendor-pubkey` directly from a source you trust (the vendor's
security.txt, their PGP-signed advisory, a community registry).

### Drand (time-lock path)

You trust the Drand quicknet beacon's threshold BLS signing scheme:
no minority of the threshold can publish a round signature before its
genesis-defined time, and the majority eventually does. If the Drand
network disappears entirely, the time-lock branch never opens — the
witness becomes recoverable only through the vendor path. That is a
graceful-degradation property of the layered envelope, not a bug.

### Sigstore Rekor (timestamp anchor)

You trust the configured Rekor instance's signed tree head. Default is
`https://rekor.sigstore.dev`; override via `ZKPOX_REKOR_URL`. Rekor
binds `bundle_hash_pre_timestamp(bundle)` to the integration time it
reports. v0.1 performs **both** the recorded-hash check (fetch the
entry and compare its `data.hash`) **and** the local Merkle inclusion
proof reconstruction. Pass `--no-network` to skip the fetch when you
can't reach Rekor — note that doing so trusts the bundle's
`inclusion_proof_hashes` without independent confirmation that the
recorded leaf matches.

### Your local clock at anchor time

The producer signs `bundle_hash_pre_timestamp` and sends it to Rekor.
Rekor's response includes `integratedTime`. The producer trusts this
number is approximately correct (within Rekor's clock-skew tolerance).
Verifiers don't trust the producer's clock; they use Rekor's recorded
time.

---

## False-positive / false-negative profile

| Predicate | False-negative probability per overflow byte | False-positive risk |
|---|---|---|
| `crash-only` (uniform `0xA5`) | `1/256` per overflow byte, BUT trivially 1 if the bug writes `0xA5` exactly. Use only for cheap sanity checks. | Only if the function legitimately writes `0xA5` outside the buffer. No current target does. |
| `memory-safety::oob-write` (position-varying) | `(1/256)^N` for `N` consecutive overflow bytes under uniform-random witness bytes. For a 14-byte overflow (target 03 max), `≈ 2^-112`. | Only if the function legitimately writes the position-varying pattern outside the buffer. Adversarially constructible if the witness generator knows the pattern table. |

### Adversarial witness generators

A producer who computes the position-varying pattern and crafts a
witness specifically to match it defeats the probabilistic redzone.
The Layer 1.x `memory-safety::shadow-allocation` predicate (registered
but unimplemented in v0.1) will replace the pattern fill with a
deterministic per-allocation shadow table, eliminating this attack
class. Until that ships, bundles produced from witnesses generated by
an adversarial producer are no stronger than the producer's good-faith
disclosure of how the witness was generated.

---

## Failure modes

### Vendor loses their age secret key before the time-lock fires

The witness is unrecoverable via the vendor path. The public proof + Rekor
anchor are still valid. The witness eventually becomes public when the
Drand round finalises (default T+90d). For high-severity bugs where the
vendor needs the witness now, the producer can issue a follow-up bundle
sealed to a fresh vendor key — but the existing bundle's timer cannot
be cancelled.

### Drand network unavailable

The time-lock branch never opens. The vendor path still works if the
vendor still has their age key. Researchers waiting for "auto-disclose
at T+90d" must publish manually (or re-anchor a new bundle with a
working alternative time-lock service).

### Vendor patches before T+90d

The producer can issue a follow-up `zkpox-prove` run with the same
witness and a shorter `--tlock-duration` (or no envelope at all). The
original bundle continues to exist and its time-lock continues to
count down; there is intentionally no "cancel" primitive — that
would require a trusted authority to retract Rekor entries.

### Vendor refuses to patch / disappears / sells the company

The bundle's time-lock fires on its original schedule regardless. The
researcher is exonerated by the Rekor timestamp; the public learns the
witness. This is the Project Zero model intentionally — rigid timers
are the only credible disclosure deterrent.

### SP1 SDK ships a soundness bug post-release

Every existing bundle's proof is suspect. There is no mechanism to
re-prove existing bundles against a patched SP1; producers must
re-issue. The verifier's `proof.system` field records the exact SP1
version used so consumers can detect "this bundle was produced under
a vulnerable prover release."

### Producer lies about `target.kind`, `target.url`, or `predicate.outputs`

`backend.verifier_key_digest`, `target.hash`, `predicate.id_canonical`,
`predicate.version`, and `outputs_bytes` are committed to the proof's
public values and cross-checked at verify time. Lying about any of
these fields is detected. `target.url` and `target.kind` are
plaintext metadata; the verifier doesn't follow URLs, so a malicious
producer could ship a bundle whose `target.url` points elsewhere — the
defence is to pass `--target <local copy>` to the verifier.

---

## How to read a bundle as a non-cryptographer

```sh
zkpox-verify path/to/bundle.cbor --json --strict
```

The JSON output names each check and its verdict (`ok` / `FAIL` / `n/a`).
The human-readable form prints the same. `--strict` promotes any
unverifiable check (missing cache, unreachable Rekor) to a hard
failure; it is the default for CI use. The lenient mode is acceptable
for casual inspection.

What you're checking:

- **structural** — the CBOR parses and required fields are well-formed.
- **vendor pubkey fingerprint** — `sha256(vendor_pubkey)` matches the
  fingerprint claim.
- **target rehash** (if `--target` supplied) — local source matches
  `bundle.target.hash`.
- **STARK proof** — `sp1-sdk` verifies the proof against the
  re-derived VK.
- **public values cross-check** — every public value matches the
  corresponding bundle field, and `inv_flag = false ∧ vuln_flag = true`.
- **Rekor recorded hash** — Rekor's stored entry for `log_index` matches
  `bundle_hash_pre_timestamp`.
- **Rekor inclusion proof** — the Merkle path reconstructs the
  `inclusion_proof_root_hash`.
- **researcher signature** — if attached, ed25519-verifies against
  `bundle_hash_pre_researcher`.

`overall_ok == true` (and exit 0) means every check that ran came back
clean. A `--strict` exit 0 means **no checks were skipped**.
