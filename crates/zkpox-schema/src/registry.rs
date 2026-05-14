//! Canonical predicate and backend ID tables.
//!
//! Every predicate and backend has BOTH a human-readable identifier
//! string (e.g. `"memory-safety::oob-write"`) and a 32-bit numeric
//! canonical ID. The string travels in the CBOR bundle for human and
//! tooling consumption; the numeric ID travels in the SP1 public
//! values where every byte committed onto the proof costs cycles.
//!
//! The mapping is **frozen by design**. New entries are append-only:
//! existing string→u32 mappings must never change, even if the
//! predicate's implementation is replaced wholesale (in which case
//! bump the predicate's `version` instead). This is exactly the
//! "protocol-version pinning" guidance in the SoK on SNARK soundness
//! vulnerabilities — drift between producer and consumer is one of
//! the more common attack surfaces.

use sha2::{Digest, Sha256};

// --- Predicate IDs ------------------------------------------------------

pub const PREDICATE_CRASH_ONLY: &str = "crash-only";
pub const PREDICATE_MEMORY_SAFETY_OOB_WRITE: &str = "memory-safety::oob-write";
pub const PREDICATE_SHADOW_ALLOCATION: &str = "memory-safety::shadow-allocation";

/// Canonical predicate registry. Pinned `(name, id)` pairs; new
/// predicates are append-only with fresh `id`s. NEVER renumber.
const PREDICATE_REGISTRY: &[(&str, u32)] = &[
    (PREDICATE_CRASH_ONLY,                  0x0000_0001),
    (PREDICATE_MEMORY_SAFETY_OOB_WRITE,     0x0000_0002),
    (PREDICATE_SHADOW_ALLOCATION,           0x0000_0003),
];

/// Resolve a predicate string to its canonical u32. Unknown strings
/// fall through to a SHA-derived ID (FNV-style truncation) so a
/// downstream caller using an experimental predicate still gets a
/// stable number — but verifiers running `--strict` will refuse it
/// because it is not in the pinned registry.
pub fn predicate_id(name: &str) -> u32 {
    for (n, id) in PREDICATE_REGISTRY {
        if *n == name {
            return *id;
        }
    }
    // Reserved high-bit range for unregistered predicates. The high
    // bit (0x8000_0000) flags "ad-hoc"; verifiers in strict mode treat
    // any ID with this bit set as unknown.
    0x8000_0000 | (sha256_truncate(name.as_bytes()) & 0x7FFF_FFFF)
}

// --- Backend IDs --------------------------------------------------------

pub const BACKEND_STATIC_C: &str = "static-c";
pub const BACKEND_RV64IM: &str = "riscv-emu";
pub const BACKEND_LLVM_IR: &str = "llvm-interp";

const BACKEND_REGISTRY: &[(&str, u32)] = &[
    (BACKEND_STATIC_C, 0x0000_0001),
    (BACKEND_RV64IM,   0x0000_0002),
    (BACKEND_LLVM_IR,  0x0000_0003),
];

/// Same convention as `predicate_id`. Unknown backends get a SHA-
/// derived ID with the high bit set so strict verifiers can reject
/// them without a separate "is this a known kind" allowlist call.
pub fn backend_id(name: &str) -> u32 {
    for (n, id) in BACKEND_REGISTRY {
        if *n == name {
            return *id;
        }
    }
    0x8000_0000 | (sha256_truncate(name.as_bytes()) & 0x7FFF_FFFF)
}

/// Enum mirror of the backend registry, useful when matching in the
/// verifier. Unknown strings map to `Unknown`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BackendKind {
    StaticC,
    Rv64Im,
    LlvmIr,
    Unknown,
}

impl BackendKind {
    pub fn from_name(name: &str) -> Self {
        match name {
            BACKEND_STATIC_C => BackendKind::StaticC,
            BACKEND_RV64IM   => BackendKind::Rv64Im,
            BACKEND_LLVM_IR  => BackendKind::LlvmIr,
            _ => BackendKind::Unknown,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            BackendKind::StaticC => BACKEND_STATIC_C,
            BackendKind::Rv64Im  => BACKEND_RV64IM,
            BackendKind::LlvmIr  => BACKEND_LLVM_IR,
            BackendKind::Unknown => "unknown",
        }
    }
}

fn sha256_truncate(bytes: &[u8]) -> u32 {
    let h = Sha256::digest(bytes);
    u32::from_be_bytes([h[0], h[1], h[2], h[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_predicate_ids_are_stable() {
        // If this test fails, someone renumbered a registered predicate.
        // That is a wire-breaking change; the test is here to catch it
        // before it ships in a bundle.
        assert_eq!(predicate_id(PREDICATE_CRASH_ONLY), 0x0000_0001);
        assert_eq!(predicate_id(PREDICATE_MEMORY_SAFETY_OOB_WRITE), 0x0000_0002);
        assert_eq!(predicate_id(PREDICATE_SHADOW_ALLOCATION), 0x0000_0003);
    }

    #[test]
    fn unregistered_predicate_has_high_bit() {
        let id = predicate_id("experimental::made-up");
        assert!(id & 0x8000_0000 != 0, "ad-hoc IDs must set the high bit");
    }

    #[test]
    fn backend_ids_are_stable() {
        assert_eq!(backend_id(BACKEND_STATIC_C), 0x0000_0001);
        assert_eq!(backend_id(BACKEND_RV64IM),   0x0000_0002);
        assert_eq!(backend_id(BACKEND_LLVM_IR),  0x0000_0003);
    }
}
