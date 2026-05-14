//! STUB — Layer 3 backend (LLVM IR / MicroRAM-style interpreter).
//!
//! This is the CHEESECLOTH-aligned mode: the target compiles to a
//! MicroRAM-like IR that the guest interprets. Program is a full
//! public input; the witness is purely the exploit. Highest
//! flexibility, highest cycle cost.
//!
//! See `docs/ROADMAP.md` for the design plan; this crate exists today
//! only so the workspace structure anticipates the addition.

#[cfg(test)]
mod tests {
    #[test]
    fn stub_crate_compiles() {}
}
