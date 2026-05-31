//! # zkpox-schema
//!
//! The bundle CBOR schema and the hashing rules that bind a bundle to
//! its components. This crate is the **only** source of truth for the
//! wire format; both `zkpox-prove` and `zkpox-verify` serialize through
//! it. The SoK-on-SNARKs guidance is explicit: protocol drift between
//! producer and consumer is one of the most common implementation
//! soundness bugs. Keep these types in lock-step.
//!
//! ## Wire version
//!
//! `BUNDLE_VERSION` is `zkpox-2.0`. It is a clean break from an earlier
//! internal schema (`v1.0`), with no compatibility shim: the verifier
//! refuses anything whose `version` field isn't an exact match. This is
//! deliberate — the v1 bundles depended on placeholder hashes that v2
//! rejects on principle.
//!
//! ## Hashing conventions
//!
//! All hashes that travel as strings use the form `sha256:HEX` (lower
//! hex, 64 chars). `target_hash` inside the SP1 public values is the
//! raw 32 bytes (not a string) — the guest commits binary, the bundle
//! re-encodes for human readability.
//!
//! ## Canonical CBOR
//!
//! `bundle_hash_pre_timestamp(bundle)` and
//! `bundle_hash_pre_researcher(bundle)` use ciborium with canonical map
//! ordering per RFC 8949 §4.2.1 so a verifier and a producer always
//! agree on the byte string being hashed regardless of dict iteration
//! order. The `with_*` helpers reset the relevant field so the same
//! `Bundle` can be hashed before and after the Rekor / researcher
//! steps without re-encoding everything.

#![deny(missing_debug_implementations)]

pub mod bundle;
pub mod hash;
pub mod public_values;
pub mod registry;

pub use bundle::*;
pub use hash::{sha256_bundle_pre_researcher, sha256_bundle_pre_timestamp, sha256_bytes, sha256_hex};
pub use public_values::{Flags, PublicValues, PUBLIC_VALUES_VERSION};
pub use registry::{
    backend_id, predicate_id, BackendKind, BACKEND_STATIC_C, BACKEND_LLVM_IR,
    BACKEND_RV64IM, PREDICATE_CRASH_ONLY, PREDICATE_MEMORY_SAFETY_OOB_WRITE,
    PREDICATE_SHADOW_ALLOCATION,
};

/// On-wire version string. Verifiers refuse anything else.
pub const BUNDLE_VERSION: &str = "zkpox-2.0";

/// Vendor envelope scheme string for the (AES-256-GCM, age, Drand
/// quicknet tlock) layered construction. Verifiers refuse other
/// schemes; the AAD is bound to this string so a future v2 envelope
/// cannot be replayed as v1.
pub const ENVELOPE_SCHEME: &str = "zkpox-aes256gcm+age+tlock-drand-quicknet/v1";

/// Sentinel scheme value when the producer chose not to seal an
/// envelope (witness available out-of-band; the proof + anchor is the
/// entire artifact). Distinct from `ENVELOPE_SCHEME` so structural
/// checks can identify the no-envelope path explicitly rather than
/// inferring from empty fields.
pub const ENVELOPE_NONE: &str = "zkpox-none/v1";

/// AAD bound to every AES-GCM ciphertext in an envelope. Bumped on any
/// breaking change to the envelope layout. An attacker who lifts an
/// AES-GCM blob from a different protocol cannot replay it through
/// zkpox-verify; the AAD mismatch surfaces on decrypt.
pub const ENVELOPE_AAD: &[u8] = b"zkpox-envelope-v1";

/// Errors raised when parsing a bundle from CBOR.
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("cbor decode: {0}")]
    Cbor(#[from] ciborium::de::Error<std::io::Error>),

    #[error("cbor encode: {0}")]
    CborEnc(#[from] ciborium::ser::Error<std::io::Error>),

    #[error("unsupported bundle version: got {got:?}, expected {expected:?}")]
    UnsupportedVersion { got: String, expected: &'static str },

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("field {field:?} has wrong shape: {detail}")]
    FieldShape { field: &'static str, detail: String },

    #[error("envelope scheme not supported: {0:?}")]
    UnsupportedEnvelopeScheme(String),

    #[error("vendor pubkey fingerprint mismatch: bundle says {bundle:?}, recomputed {computed:?}")]
    VendorFingerprintMismatch { bundle: String, computed: String },
}

pub type Result<T> = core::result::Result<T, SchemaError>;
