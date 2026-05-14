# DESIGN — Architecture + literature anchoring

This document covers the *why* behind zkpox's architecture. For the wire
format see `BUNDLE-FORMAT.md`; for the predicate library see
`PREDICATES.md`; for the failure model see `THREAT-MODEL.md`; for what
the current code does and does not assert see `SCOPE.md`.

## 1. Statement the prover proves

The formal proof statement, in the style of CHEESECLOTH §3:

> ∃ witness `w` such that:
> Backend.run(predicate, `w`) executes successfully (`inv_flag = false`)
> AND Backend.run(predicate, `w`) detected the predicate's violation
> (`vuln_flag = true`) AND the public outputs committed by the SP1
> guest are exactly:
>   (target_hash, predicate_id, predicate_version,
>    backend_id, backend_version,
>    inv_flag, vuln_flag, outputs_bytes).

Public outputs are committed immutably by SP1's STARK; the witness `w`
is never revealed by the proof. Witness confidentiality is then layered
on top by the disclosure envelope.

## 2. The two-flag (CHEESECLOTH) discipline

We adopt CHEESECLOTH's `inv_flag` + `vuln_flag` directly (§3 of the
CHEESECLOTH paper). The rationale is sharp: a zero-knowledge proof of
"my predicate fired" is sound only if you also prove that the execution
itself was faithful. Otherwise an adversarial prover could trivially
fire the predicate by violating the runtime invariants the predicate
depends on.

In CHEESECLOTH's MicroRAM model:

- `inv_flag` is set to `true` if any of the runtime checks
  (memory-consistency, instruction-decode, allocation-tracking) failed
  during execution. The verifier requires `inv_flag = false`.
- `vuln_flag` is set to `true` if the predicate's check fired. The
  verifier requires `vuln_flag = true`.

In zkpox's Layer 1 (static-C) backend, `inv_flag` is always `false` —
the freestanding C compiled into the guest cannot violate the SP1
zkVM's runtime invariants in a way that's visible at the predicate
level. The slot is preserved in the public-values schema so Layers 2
and 3 (RV64IM emulator, LLVM IR) can write into it.

## 3. Why SP1, not a custom circuit / Mac'n'Cheese / CHEESECLOTH

CHEESECLOTH produces R1CS / SIEVE IR circuits and uses Mac'n'Cheese
(VOLE-based) ZK protocols. That stack is more flexible but
substantially harder to integrate (MicroRAM compiler, Swanky library,
network-coordinated multi-round interaction).

SP1 is a STARK zkVM that lets us *run Rust code* inside the prover.
The cost: every cycle inside the zkVM is expensive, so the predicates
have to be tight. The benefit: the entire toolchain compiles, and the
verifier is a small library call rather than a multi-round protocol.

The trade-off vs Cheesecloth's approach:

| Concern | CHEESECLOTH | zkpox (SP1) |
|---|---|---|
| Program as public input | Yes (MicroRAM bytecode) | Linked into the guest ELF; the VK digest binds it. |
| Proof system | VOLE-based interactive ZK (Mac'n'Cheese, Swanky) | Non-interactive STARK with optional Groth16 wrap |
| Proof size | Multi-MB (interactive transcript) | ~2.65 MB (raw STARK), ~1.7 KB (Groth16-wrapped) |
| Verifier complexity | Multi-round protocol implementation | One library call (`sp1_sdk::ProverClient::verify`) |
| Memory-safety predicates | Per-op shadow-table checks in MicroRAM | Redzone scanner today; shadow-allocation table planned |
| Adding a target | Recompile via the MicroRAM LLVM backend | Recompile the guest with a new target C |
| Adding a predicate | Edit the MicroRAM compiler pass | Implement the `Predicate` trait |

The SP1 path is right for v0.1 because the audited toolchain is the
production-ready one *today*. As CHEESECLOTH-style flexibility matures
(or as SP1's WHIR / FRI improvements close the gap), the layered
backend architecture lets us swap in alternative provers without
disturbing the bundle schema.

## 4. The backend layering

Three backend layers are anticipated by the bundle schema:

1. **`static-c`** (Layer 1, **working** in v0.1) — the target C source
   is linked into the SP1 guest ELF. The VK digest is the binding for
   target identity. One guest ELF per (target, predicate) pair, cached
   on disk.

2. **`riscv-emu`** (Layer 2, stub) — the target is a precompiled RV64IM
   binary; the guest interprets it. Program becomes part of the public
   input (the guest hashes it on the way in; the hash becomes
   `target_hash`). One guest ELF per *predicate* — much cheaper to
   distribute.

3. **`llvm-interp`** (Layer 3, stub) — closest to CHEESECLOTH:
   target is LLVM IR or MicroRAM bytecode the guest interprets. Most
   flexible for cross-language targets (C, C++, Rust); highest cycle
   cost.

The schema's `backend.kind` + `backend.id_canonical` + `backend.version`
fields, together with the SP1 `verifier_key_digest`, give a verifier
all the information needed to decide whether it understands the bundle
without a binding break.

## 5. Predicates as a versioned library

Every predicate has:

- A canonical string ID (e.g. `memory-safety::oob-write`).
- A 32-bit numeric ID, pinned in `zkpox-schema::registry`. Never
  renumbered. New predicates are append-only.
- A `version` integer. Bumped on any behavioural change.
- A registered set of compatible backends.

Verifiers consume the canonical ID + version directly from the proof's
public values, so a producer lying about which predicate fired is
detected.

The decision to ship predicates as a library, not a circuit, mirrors
CHEESECLOTH's predicate catalogue (their Table 1). The difference: we
ship the predicate as runtime Rust code, not as a compiler pass — the
predicate runs **inside** the zkVM, observing memory accesses through
the redzone or (future) shadow table.

## 6. Bundle = proof + disclosure surface

The CBOR bundle is what gets distributed publicly. It contains:

- The STARK proof and its public values (the *what* of the claim).
- The vendor envelope (encrypted witness, two recovery paths).
- The Rekor anchor (the *when* — public, tamper-evident time-stamp).
- Researcher attribution + signature (optional; anonymity is supported).

The envelope is the CVD-pipeline-aware part: it implements
Project-Zero-style 90-day disclosure as a property of the artifact
itself. A vendor gets the witness immediately via age-decrypt; the
public gets it after the Drand round fires. There is no manual
escrow, no third-party notary, no policy enforcement out-of-band.

The hashing rules (`bundle_hash_pre_timestamp`,
`bundle_hash_pre_researcher`) are designed so the bundle can be
incrementally finalised: anchor first, then sign, or sign first then
anchor — both produce a valid bundle whose hashes binds the right
content to the right downstream artifact.

## 7. Trust roots and what the verifier actually checks

A `--strict` verify performs eight distinct checks (see SCOPE.md §"How
to read a bundle as a non-cryptographer"). The trust assumptions are
spelled out in THREAT-MODEL.md. The architectural commitment is that
all eight checks run **without any RAPTOR or zkpox-specific oracle** —
the verifier needs:

- The bundle CBOR.
- (Optionally) a local copy of the target source for the rehash check.
- (Optionally) network access to Rekor.
- The SP1 toolchain locally OR the cached guest ELF for the (target,
  predicate) pair the bundle commits to.

That last point is the cost of Layer 1's static-C approach: verifiers
need the SP1 toolchain to derive the reference VK digest from the
guest ELF. Layer 2's `riscv-emu` removes this — the guest ELF is
universal across all targets and can be a published artifact the
verifier downloads once.

## 8. References

- **CHEESECLOTH** — Cuéllar, Harris, Parker, Pernsteiner, Tromer.
  *"Cheesecloth: Zero-Knowledge Proofs of Real World Vulnerabilities."*
  USENIX Security 2023; extended journal version, ACM TOPS 2025.
  Source of the two-flag discipline, the memory-safety predicate
  catalogue, the MicroRAM abstraction, and the "program-as-public-
  input" framing we adopt for Layers 2/3.
- **Trail of Bits + DARPA SIEVE** — Bain, Mistal, Roberts, et al.
  "Reinventing Vulnerability Disclosure Using Zero-Knowledge Proofs."
  Trail of Bits blog, 2020; eprint 2022/1223. The original MSP430
  demonstration that this pipeline is feasible for embedded software.
- **SP1** — Succinct Labs. STARK-based zkVM with audited release lines.
  zkpox v0.1 pins SP1 6.0.1.
- **Drand quicknet** — distributed randomness beacon, 3-second period,
  unchained BLS signatures on G1. We hardcode quicknet's chain hash
  and group public key into `zkpox-envelope`; verifiers do not need
  network access at seal time, only the witness consumer needs network
  at decrypt time.
- **Sigstore Rekor** — append-only transparency log. v0.1 verifies
  both the recorded-hash and the Merkle inclusion proof.
- **RFC 6962** — Certificate Transparency. Source of the Merkle leaf
  / internal-node hashing convention Rekor follows.
- **SoK on SNARK soundness vulnerabilities** — eprint 2024/514. Source
  of the protocol-version-pinning and strict-input-validation
  guidance baked into the bundle schema and the verifier's strict
  mode.
