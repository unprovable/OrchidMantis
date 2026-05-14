//! # zkpox-predicates
//!
//! The predicate library. A **predicate** (CHEESECLOTH calls these
//! "vulnerability classes") is the formal definition of what counts
//! as the violation a proof is asserting. Each predicate lives as a
//! small Rust module here; the SP1 guest invokes one of them against
//! the target program and the prover's witness.
//!
//! ## Design intent
//!
//! 1. **Audited per-predicate.** A predicate is a tight, reviewable
//!    chunk of Rust whose semantics fit on a single page. Bugs in a
//!    predicate undermine every proof that depends on it; the
//!    library version-locks each predicate so a verifier can refuse
//!    to accept anything below a known-good version.
//!
//! 2. **Pluggable.** New predicates implement the `Predicate` trait
//!    and register their string + canonical-u32 ID in
//!    `zkpox-schema::registry`. The guest's dispatch picks the
//!    requested predicate at build time (so each guest ELF binds one
//!    predicate); the bundle records both the predicate identifier
//!    and the SP1 verifying-key digest produced.
//!
//! 3. **CHEESECLOTH discipline.** Every predicate produces a
//!    `(outputs, inv_flag, vuln_flag)` triple per CHEESECLOTH:
//!      - `inv_flag = false` ⇔ the execution committed no invariant
//!        violation (the prover ran the program faithfully).
//!      - `vuln_flag = true`  ⇔ the predicate observed the violation.
//!      The proof is accepted only if `inv_flag = false ∧ vuln_flag = true`.
//!
//! 4. **No serde in the guest.** Outputs are encoded with a tiny
//!    hand-rolled wire format (`outputs::Buf`) so the guest doesn't
//!    need to pull in serde/ciborium. The host re-decodes these
//!    bytes into a CBOR `Value` for the bundle.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod outputs;
pub mod redzone;

pub use outputs::{Buf, ToWire};

/// What kind of memory the predicate is looking at. Currently only
/// `Stack` is meaningful (the predicates here run against
/// stack-resident buffers). Heap-aware predicates are future work
/// (`shadow-allocation`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BufferKind {
    Stack,
}

/// The target the predicate exercises. Implemented per-target by the
/// guest's static-C bindings (or, in future, by the RV64IM /
/// LLVM-IR backends).
pub trait TargetRunner {
    /// Invoke the target. Implementations are unsafe to write but
    /// safe to call from inside the predicate; the safety contract is
    /// "this function won't dereference memory outside the supplied
    /// buffer or read past `n` bytes of `input`."
    fn invoke(
        &self,
        buf: *mut core::ffi::c_char,
        buf_size: usize,
        input: *const core::ffi::c_char,
        n: usize,
    );

    /// The target's logical buffer size — the predicate uses this to
    /// know where the legitimate buffer ends and the redzone begins.
    fn buf_size(&self) -> usize;
}

/// The predicate trait. Every predicate is a zero-sized type whose
/// associated constants are the registry entries and whose `run`
/// is the actual check.
///
/// The `Outputs` type is whatever the predicate wants to emit — for
/// `MemorySafetyOobWrite` that's `{ count, first_offset }`. The
/// host crate decodes these bytes back into structured fields.
pub trait Predicate {
    /// String ID, must match an entry in `zkpox_schema::registry`.
    const ID: &'static str;
    /// Canonical u32 ID — keep in sync with `predicate_id(ID)`.
    const ID_CANONICAL: u32;
    /// Predicate version. Bumped on any behavioural change.
    const VERSION: u32;
    /// Outputs type; see the predicate's module-level docs for
    /// semantics.
    type Outputs: ToWire;

    /// Execute the predicate against the supplied target and witness.
    /// Returns `(outputs, inv_flag, vuln_flag)`.
    fn run<T: TargetRunner>(target: &T, witness: &[u8]) -> (Self::Outputs, bool, bool);
}
