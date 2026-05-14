# THREAT-MODEL — who trusts what

Companion to `SCOPE.md` (the user-facing trust statement). This file
breaks the trust roots down by adversary and capability so reviewers
can reason about which mitigations cover which attacks.

## Actors

| Actor | Role |
|---|---|
| **Researcher** | Holds the exploit; produces the bundle. |
| **Vendor** | The author / maintainer of the target software. Can decrypt the witness immediately via the age path. |
| **Public** | Reads the bundle. Eventually (after the time-lock) can decrypt the witness. |
| **SP1 prover/verifier** | The audited zkVM machinery. |
| **Drand network** | Threshold BLS signer for the time-lock. |
| **Sigstore Rekor** | Append-only transparency log for the anchor. |
| **Adversary** | An attacker against any of the above. |

## Adversary capabilities & mitigations

| Capability | What they could try | Mitigation |
|---|---|---|
| Forging a STARK | Submit a fake proof claiming an exploit they don't have. | SP1's audited STARK soundness. Verifier rejects on `client.verify(...)` failure. **Largest single risk in the trust chain** — pin SP1 version and watch for advisories. |
| Lying about the target | Bundle says `target.url = upstream.example.com/foo.c` but ships a proof against a different program. | Verifier re-derives `verifier_key_digest` from the cached guest ELF for `(target_hash, predicate, sp1)` and asserts it matches `bundle.backend.verifier_key_digest`. Verifier also accepts `--target <local path>` to re-hash. |
| Lying about the predicate | Bundle says `predicate.id = oob-write` but the guest actually ran `crash-only`. | The proof's public values commit `predicate_id_canonical` AND `predicate_version`; the verifier cross-checks against the bundle. Mismatch is fatal. |
| Lying about predicate outputs | Bundle says `outputs.count = 10` but the proof actually reported `1`. | The proof's public values commit `outputs_bytes` (the canonical wire form). The verifier re-decodes these and compares to `bundle.predicate.outputs`. Mismatch is fatal. |
| Replaying a bundle under v1 framing | Lift a v2 bundle's payload, change `version = "zkpox-2.0"` → `"zkpox-1.0"`, hand to a v1 verifier. | v1 doesn't ship (zkpox is v2.0 on first release); verifiers refuse any other `version` string. |
| Replaying an envelope from a different protocol | Lift a victim's AES-GCM blob from some other system, embed in a fake bundle. | AES-GCM AAD is the constant `zkpox-envelope-v1`. Decrypt fails on mismatch. |
| Encrypting to a forged "vendor key" | Producer claims `vendor_pubkey = age1evil`, vendor never sees the witness. | Vendor-key registry problem; v0.1 punts to the operator. Verifier checks `sha256(vendor_pubkey) == vendor_pubkey_fingerprint` (catches accidental corruption, not malicious substitution). Real solution: a curated registry (community-maintained or CISA / FIRST). |
| Substituting researcher signature | Strip a real researcher's signature and add a fake one. | The signature is over `bundle_hash_pre_researcher(bundle)` and ed25519-verifies against the included pubkey. The pubkey itself is bound to whoever published it (researcher's social trust). |
| Pre-anchoring | Submit a proof to Rekor *before* the proof actually exists, to claim a fake earlier integrated_time. | Rekor's `data.hash` is over a hash the producer signed. Without the actual bundle (which contains the proof), the recorded hash is meaningless — no verifier can derive the same hash without the proof. Pre-anchoring doesn't help. |
| Suppressing the time-lock | Vendor never reveals the witness; researcher's tlock blob is the only public path. | Default 90-day Drand round automatically fires. No suppression possible unless Drand itself disappears. |
| Soundness bug in SP1 | A new SP1 bug lets the adversary forge proofs. | All existing bundles become suspect. Verifiers pin `sp1-zkvm` and `sp1-sdk` versions; `proof.system` records the exact version. Bundles produced under vulnerable releases are easy to enumerate; the producer can re-issue under a patched release. |
| Soundness bug in age / aes-gcm | The vendor envelope leaks `K` to an attacker who shouldn't have it. | The proof itself stays sound — only the witness's confidentiality is broken. Disclosure of the witness is what the time-lock would have done eventually anyway; the leak only moves the public-disclosure forward in time. |
| Soundness bug in tlock | An attacker reads `K` before the Drand round fires. | Same as above: confidentiality breaks early; the proof is unaffected. |
| Soundness bug in Rekor | An attacker fabricates an inclusion proof for a leaf that was never recorded. | The *timestamp* binding breaks for affected bundles. The proof itself is unaffected; researchers wanting strong time priority can dual-anchor (multiple Rekor instances; community-maintained transparency logs). |
| Malicious Rekor instance | Producer or verifier points at a private Rekor that reports false `integratedTime`. | Defaults to public `https://rekor.sigstore.dev`. `ZKPOX_REKOR_URL` is documented as an override; reviewers should check it explicitly. |
| Adversarial witness against the redzone predicate | Producer crafts overflow bytes that match the position-varying pattern table, hiding the violation. | Probabilistic redzone is defeatable. Document the limit in `SCOPE.md` and `PREDICATES.md`. Resolved structurally by `memory-safety::shadow-allocation` (planned). |

## Trust assumptions, summarised

A verifier accepting a bundle as valid relies on:

1. **SP1's STARK is sound** — pinned to a specific audited release.
2. **sha256 is collision-resistant** — used for target identity,
   verifier-key identity, vendor-pubkey fingerprint, and the bundle
   anchor hash.
3. **age's X25519 / ChaCha20-Poly1305 is sound** — used for the vendor
   recovery path.
4. **AES-256-GCM is sound** — used for the witness payload encryption.
5. **Drand quicknet's threshold BLS is sound** — used for the time-lock.
6. **The chosen Rekor instance's signed tree head is sound** — used for
   the anchor.
7. **ed25519 is sound** — used for the researcher signature and the
   anchor identity.
8. **The producer's claim about the target is honest** — defeatable
   by passing `--target <local path>` to the verifier.

The single point of failure most worth attention is #1: SP1 itself.
Soundness bugs in zkVMs are not theoretical. The Trail of Bits work
that found exploitable bugs in Google's specialized ZK prover (2022)
and the routine findings from Arguzz / zkFuzz / Circuzz against
production zkVM releases make this the lowest-margin assumption in
the stack. Mitigation: pin a specific audited release; require
release-time security advisory subscriptions for operators using
zkpox in real disclosure pipelines.
