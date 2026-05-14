//! The SP1 public-values layout.
//!
//! These are the bytes the SP1 guest commits as the proof's public
//! output. The host reads them back via `proof.public_values`. The
//! verifier reads them and asserts they are consistent with the
//! corresponding fields in the CBOR bundle.
//!
//! ## Field order
//!
//! The order below is the wire order; the guest commits in exactly
//! this order, and `PublicValues::read_from_sp1` reads in exactly
//! this order. Any reordering is a wire-breaking change — bump
//! `PUBLIC_VALUES_VERSION`.
//!
//! ```text
//! version           u32      (defensive — see "Version pinning" below)
//! target_hash       [u8; 32] (sha256 of the target source bytes)
//! predicate_id      u32      (PREDICATE_REGISTRY)
//! predicate_version u32      (predicate impl version; freeze with the ID)
//! backend_id        u32      (BACKEND_REGISTRY)
//! backend_version   u32
//! flags             u32      (bitfield, see Flags::*)
//! outputs_len       u32
//! outputs_bytes     [u8; outputs_len]   (CBOR of Predicate::Outputs)
//! ```
//!
//! ## Version pinning
//!
//! `version` is committed first deliberately. A verifier that reads
//! the public values from a proof produced under a different schema
//! version will see the version word first and can fail before
//! interpreting the rest. The verifier asserts
//! `version == PUBLIC_VALUES_VERSION`; without this check, a
//! schema-v3 bundle replayed under a schema-v2 verifier would
//! mis-parse offsets and could pass spuriously.

/// The version word committed as the first public value. Bump on any
/// change to this layout, even reordering.
pub const PUBLIC_VALUES_VERSION: u32 = 2;

/// Two-flag CHEESECLOTH discipline: `inv_flag` says "no constraint was
/// violated during execution" (i.e. the trace is valid); `vuln_flag`
/// says "the predicate observed the violation we are claiming."
///
/// The verifier requires `inv_flag == false ∧ vuln_flag == true`.
/// Both bits set, only `vuln`, or only `inv` are all rejected: the
/// proof must witness a valid execution AND the predicate firing.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Flags {
    InvFlag  = 0b01,
    VulnFlag = 0b10,
}

impl Flags {
    pub fn pack(inv: bool, vuln: bool) -> u32 {
        (inv as u32) | ((vuln as u32) << 1)
    }
    pub fn unpack(bits: u32) -> (bool, bool) {
        (bits & 0b01 != 0, bits & 0b10 != 0)
    }
}

/// In-memory mirror of the public values as parsed back from SP1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicValues {
    pub version:           u32,
    pub target_hash:       [u8; 32],
    pub predicate_id:      u32,
    pub predicate_version: u32,
    pub backend_id:        u32,
    pub backend_version:   u32,
    pub inv_flag:          bool,
    pub vuln_flag:         bool,
    pub outputs_bytes:     Vec<u8>,
}

impl PublicValues {
    pub fn new(
        target_hash: [u8; 32],
        predicate_id: u32,
        predicate_version: u32,
        backend_id: u32,
        backend_version: u32,
        inv_flag: bool,
        vuln_flag: bool,
        outputs_bytes: Vec<u8>,
    ) -> Self {
        Self {
            version: PUBLIC_VALUES_VERSION,
            target_hash,
            predicate_id,
            predicate_version,
            backend_id,
            backend_version,
            inv_flag,
            vuln_flag,
            outputs_bytes,
        }
    }
}
