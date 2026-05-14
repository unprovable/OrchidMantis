//! STUB — Layer 2 backend (RV64IM binary emulator).
//!
//! This crate is intentionally empty in v0.1. It exists so the
//! workspace is shaped for the Layer 2 addition rather than retrofitted
//! later. See `docs/ROADMAP.md` for the design notes.
//!
//! The plan is to embed a small RV64IM interpreter inside the SP1
//! guest, accept program bytes as part of the witness (committed to a
//! public hash on the way in), and run the same predicate library
//! against the emulator's observable memory accesses.

#[cfg(test)]
mod tests {
    #[test]
    fn stub_crate_compiles() {
        // Doc-test surrogate: prove `cargo build` still completes.
    }
}
