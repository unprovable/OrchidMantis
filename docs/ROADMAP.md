# ROADMAP

## v0.1 (this release)

- Layer 1 backend (`static-c`): freestanding C source linked into the
  SP1 guest.
- Two predicates: `crash-only`, `memory-safety::oob-write`.
- Pure-Rust envelope: AES-256-GCM + age + Drand quicknet tlock.
- Pure-Rust Rekor anchor + RFC 6962 inclusion-proof verification.
- Schema-pinned canonical IDs for predicates and backends.
- Real SP1 verifying-key digest bindings (no placeholder hashes).
- 25 unit tests across the workspace.

## v0.2 — verifier hardening + envelope polish

- Researcher-signed Rekor entry (currently the anchoring identity is
  ephemeral and discarded; v0.2 lets researchers anchor under their
  own published ed25519 identity).
- Sigstore Rekor signed-tree-head signature verification (current
  v0.1 verifies the Merkle path against the embedded root; v0.2
  additionally verifies that root with the log's published public
  key).
- Vendor-key registry plumbing: support a `--vendor-from-domain
  vendor.example.com` flag that reads the vendor's security.txt over
  HTTPS, verifies a signature on the pubkey from a community-trusted
  set, and uses the resulting recipient.
- Bundle index format: a JSON catalogue listing N bundles by
  `(target_hash, predicate, integrated_time)` so a maintainer can
  publish "every CVE we've proved" as one file.

## v0.3 — shadow-allocation predicate

Implement `memory-safety::shadow-allocation`:

- A parallel shadow address space the guest maintains.
- Per-store instrumentation marking which buffer (and which byte
  ranges) is legitimately writable.
- OOB writes are detected exactly, regardless of overflow byte
  values. Defeats the adversarial-witness pattern-matching attack
  documented in `docs/PREDICATES.md`.
- The corresponding `memory-safety::oob-read` predicate (read-side
  symmetric) becomes feasible since the shadow state distinguishes
  initialized from uninitialised bytes.

## v0.4 — Layer 2: RV64IM emulator backend

Embed a minimal RV64IM interpreter inside the SP1 guest:

- Witness format: program bytes (committed publicly as
  `target_hash`) plus the exploit input.
- The guest emulates the program; predicates observe its memory
  accesses through the same redzone or shadow-allocation
  interfaces.
- One universal guest ELF; no recompile per target. Distribution
  becomes a single binary.
- Massive cycle-cost penalty (likely 100x+ vs. native execution),
  but flexibility for any target compilable to RV64IM.

The crate `zkpox-backend-rv64im` is reserved for this.

## v0.5 — Control-flow predicates

`cfi::pc-attacker-controlled` — proves the program counter took a
value derived from witness-controlled memory. Requires the RV64IM
emulator backend so the guest can introspect the program counter.

`cfi::indirect-call-corruption` — proves an indirect-call target
came from witness-controlled memory.

These are the predicates that move zkpox from "proves a memory
violation" to "proves control-flow hijack." See `docs/SCOPE.md`'s
"what zkpox does NOT prove" section.

## v0.6 — Information-leak predicate

`info-leak::secret-to-public-sink` — CHEESECLOTH-style storage-
labeling proof that witness-controlled bytes labelled "secret"
reached a function labelled "public sink" via observable program
output. Requires a labelling pass over the target source.

Demonstrates the same predicate the CHEESECLOTH paper used for its
Heartbleed proof.

## v0.7 — Layer 3: LLVM IR / MicroRAM backend

The CHEESECLOTH-aligned path. Closer to the academic precedent and
maximally flexible across source languages (C, C++, Rust). Highest
implementation cost — likely a separate crate that vendors a tiny
LLVM-IR-to-MicroRAM compiler.

The crate `zkpox-backend-llvm-ir` is reserved for this.

## v1.0 — stable wire format + flip experimental flag

When the above ships, bump `experimental = false` for all newly
produced bundles. Verifiers refuse `experimental = true` bundles for
real CVD pipelines, with explicit `--experimental-ok` opt-in for
testing.

## Future / open-ended

- **EVM backend** (a parallel to Layer 2). Predicates:
  `evm::balance-drain`, `evm::auth-bypass`, `evm::reentrancy`.
  Integration with bug-bounty platforms (Immunefi, Sherlock).
- **GPU acceleration**. SP1's GPU prover (currently CUDA, RISC0 has
  Metal variants) drops proving time substantially. No code changes
  here — once `sp1-sdk`'s CudaProver feature stabilises, set
  `SP1_PROVER=cuda` and the existing prover uses it.
- **Witness encryption with proof-derived keys**. *NOT* deployable
  with current cryptography. Documented here only to be explicit
  about refusing requests for it: Garg-Gentry-Sahai-Waters witness
  encryption depends on multilinear maps that are broken. Do not
  ship this even if asked. The age + tlock hybrid is the practical
  alternative.
- **Bundle aggregation**. One Groth16 wrap proving a *batch* of
  predicates fired across a *batch* of targets. Useful for
  "snapshot of every memory-safety bug in this codebase." Requires
  STARK-to-SNARK recursion which SP1 supports — engineering, not
  research.

## Out-of-scope, indefinitely

- Side-channel proofs (timing, cache, EM, power). zkVMs model
  software, not silicon.
- Speculative-execution bugs (Spectre, Meltdown, Downfall, etc.).
- Concurrency / weak-memory bugs (TOCTOU, data races).
- Cooperative-multitasking exploit chains.
