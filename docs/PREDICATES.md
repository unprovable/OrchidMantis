# PREDICATES — the predicate library

A **predicate** in zkpox is the formal definition of what counts as
the violation a proof asserts. Predicates live as small Rust modules
under `crates/zkpox-predicates/`. Each is auditable, versioned, and
referenced by canonical ID from the bundle schema's pinned registry
(`zkpox-schema::registry`).

## Catalogue (v0.1)

| ID | Canonical ID | Status | Outputs |
|---|---|---|---|
| `crash-only` | `0x0000_0001` | shipping | `{ crashed: bool }` |
| `memory-safety::oob-write` | `0x0000_0002` | shipping | `{ count: u32, first_offset: i32 }` |
| `memory-safety::shadow-allocation` | `0x0000_0003` | registered, not implemented | TBD |

The registry's high bit (`0x8000_0000`) is reserved for ad-hoc
predicates not in the pinned table. Verifiers running `--strict`
refuse them.

## `crash-only`

The cheapest predicate. Uniform `0xA5` canary around the buffer; flags
any byte of the redzone whose post-call value isn't `0xA5`.

- **False-negative**: trivially defeated whenever the bug writes `0xA5`
  exactly. Use only for low-severity bugs where a stronger predicate
  is overkill.
- **Cost**: cheapest of any predicate; ~one byte per redzone slot.
- **Output**: a single `crashed: bool`.

## `memory-safety::oob-write`

Position-varying pattern fill:

```
pattern_byte(p) = 0xA5 XOR ((p * 0x9E37_79B1) >> 24)
```

Every redzone byte has a distinct expected post-call value. An
attacker who didn't pre-compute the pattern matches any single
position with probability `1/256`; matching `N` consecutive overflow
bytes drops to `(1/256)^N`.

- **False-negative**: `(1/256)^N` for `N` consecutive overflow bytes
  under uniform-random witness bytes. Negligible for `N ≥ 4`.
- **Adversarial witness defeat**: a producer who computes the pattern
  table can craft overflow bytes that match it exactly. Mitigated by
  `memory-safety::shadow-allocation` (planned).
- **Cost**: identical to `crash-only` for the predicate; the cost
  difference is in the redzone fill (one xor per byte at setup time).
- **Outputs**:
  - `count: u32` — total redzone bytes that disagreed with the pattern.
  - `first_offset: i32` — signed offset of the first such byte from
    `buf[0]`. Negative means underflow; positive means overflow. `i32::MIN`
    is reserved for "no violation observed" (guarded by `count == 0`).

## `memory-safety::shadow-allocation` (planned, v1.x)

Replaces the probabilistic redzone with a deterministic ASan-style
shadow table:

- Every store inside the target is instrumented (via a shadow-store
  on a parallel address space the guest maintains).
- Out-of-bounds writes are detected exactly; no probabilistic gap.
- Defeats the adversarial-witness pattern-matching attack at the cost
  of additional zkVM cycles per memory access.

This is the v1.x research priority. The bundle schema and registry
already reserve the canonical ID; an implementation lands in a
dedicated PR with full predicate tests.

## Future predicates (roadmap)

These are NOT in `zkpox-schema::registry` yet — they will be added
when the implementation lands. ID space `0x0000_0010` onwards is held
for them so the current `0x0000_000F` range stays free for
memory-safety follow-ons.

- `memory-safety::oob-read` — symmetric to oob-write, for info-leak.
  Requires the shadow allocation table.
- `memory-safety::uaf` — read/write to a freed allocation. Requires
  an allocation-state tracker inside the guest.
- `memory-safety::double-free` — calling `free` twice on the same
  allocation.
- `cfi::pc-attacker-controlled` — instruction pointer assumes a value
  derived from witness-controlled memory. Requires the RV64IM
  emulator backend (Layer 2) since the static-C backend doesn't expose
  the program counter.
- `info-leak::secret-to-public-sink` — CHEESECLOTH-style
  storage-labeling proof that witness-controlled bytes reached a sink
  function labelled public. Requires a labelling scheme in the guest.
- `evm::balance-drain`, `evm::auth-bypass`, `evm::reentrancy` —
  smart-contract predicates. Need an EVM backend (a sister to Layer 2).

## Writing your own predicate

Implement the `Predicate` trait from `zkpox-predicates::Predicate`:

```rust
use zkpox_predicates::{outputs::ToWire, Predicate, TargetRunner};

pub struct MyPredicate;

impl Predicate for MyPredicate {
    const ID: &'static str = "my-org::my-check";
    const ID_CANONICAL: u32 = 0x8000_0042; // ad-hoc; high bit set
    const VERSION: u32 = 1;
    type Outputs = MyOutputs;

    fn run<T: TargetRunner>(target: &T, witness: &[u8]) -> (Self::Outputs, bool, bool) {
        // Set up your instrumented memory.
        // Call target.invoke(...).
        // Inspect post-call state.
        let outputs = MyOutputs { /* ... */ };
        let inv_flag = false;
        let vuln_flag = /* did your check fire */;
        (outputs, inv_flag, vuln_flag)
    }
}
```

The trait's `run` signature is intentionally constrained to *the
checks*. The guest crate wires the predicate into its public-values
commit; the host crate handles witness-decoding and bundle assembly.

**Strict rules** for accepting a predicate into the shipped library:

1. Register the canonical ID in `zkpox-schema::registry`. Use the
   next free slot below `0x0001_0000`; do not reuse retired IDs.
2. Write a `Predicate::run` that does NOT depend on any host-side
   state. The proof is over the guest's execution; predicates that
   read clock, syscall, or other external state are unsound under
   the zkVM model.
3. Provide a corpus of `(witness, expected outputs)` pairs in
   `tests/corpus/` so the predicate's expected behaviour is exercised
   by `cargo test`.
4. Document the false-positive / false-negative profile in
   `docs/PREDICATES.md` (this file) and add the predicate to
   `docs/SCOPE.md`'s catalogue table.
5. Choose `version = 1` for the initial implementation; bump on any
   change to the predicate's wire output, its detection logic, or its
   security claims.

## Predicate-version migration

Adding a new predicate is append-only and safe. **Changing** a
predicate's behaviour is a wire-breaking event:

- Bump `VERSION`.
- Verifiers shipping the old version refuse the new bundle (the
  `--strict` allowlist is keyed on the canonical ID; the version cross-
  check is in the SP1 public values).
- The producer's bundle records both `predicate.id_canonical` and
  `predicate.version`, so a verifier can pin "I accept v1 only" while
  a separate verifier installation accepts v2.

This mirrors the "protocol-version pinning" guidance from the SoK on
SNARK soundness vulnerabilities (eprint 2024/514): every wire boundary
carries its version, and downstream consumers refuse anything
unrecognised.
