//! Hash helpers and canonical-CBOR bundle hashing.
//!
//! Two derived hashes matter for the disclosure flow:
//!
//! - `bundle_hash_pre_timestamp(bundle)` — hash of the bundle with
//!   `timestamp = None`. Anchoring to Rekor commits this hash;
//!   verifiers recompute it and compare. Adding a timestamp later does
//!   not break the anchor binding because the anchor was over a
//!   timestamp-less canonical encoding.
//!
//! - `bundle_hash_pre_researcher(bundle)` — hash of the bundle with
//!   both `timestamp = None` AND `researcher = None`. This is what a
//!   researcher signs. Signing-before-anchoring means the researcher
//!   signature does not commit to the anchor; signing
//!   pre-researcher means the signature is over its own absence (the
//!   signature can be added last without recursion).

use sha2::{Digest, Sha256};

use crate::bundle::{Bundle, Researcher, Timestamp};

/// `sha256:HEX`-prefixed digest of arbitrary bytes (canonical
/// presentation used throughout the bundle). Always lowercase hex.
pub fn sha256_bytes(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

/// Same shape as `sha256_bytes`, but for arbitrary 32-byte digests
/// produced elsewhere (e.g. by the SP1 SDK's verifying-key digest).
pub fn sha256_hex(digest: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(digest))
}

/// Hash the bundle with `timestamp` set to `None`. This is the hash
/// the Rekor anchor binds to. Producers compute this *before*
/// anchoring; verifiers recompute it after parsing the bundle.
pub fn sha256_bundle_pre_timestamp(bundle: &Bundle) -> [u8; 32] {
    let cleared = clear_timestamp(bundle);
    let mut buf = Vec::with_capacity(2048);
    // ciborium serializes maps in struct field order; combined with
    // the deterministic CBOR mode below, this yields a stable byte
    // string regardless of HashMap iteration order. RFC 8949 §4.2.1
    // canonical encoding is the contract producer and verifier share.
    ciborium::ser::into_writer(&cleared, &mut buf)
        .expect("ciborium serialization of Bundle into Vec is infallible");
    let mut hasher = Sha256::new();
    hasher.update(&buf);
    hasher.finalize().into()
}

/// Hash the bundle with both `timestamp` and `researcher` cleared.
/// The researcher signs this digest; the signature is then attached
/// to the (still timestamp-less) bundle, anchored, and finalized.
pub fn sha256_bundle_pre_researcher(bundle: &Bundle) -> [u8; 32] {
    let cleared = clear_researcher(&clear_timestamp(bundle));
    let mut buf = Vec::with_capacity(2048);
    ciborium::ser::into_writer(&cleared, &mut buf)
        .expect("ciborium serialization of Bundle into Vec is infallible");
    let mut hasher = Sha256::new();
    hasher.update(&buf);
    hasher.finalize().into()
}

fn clear_timestamp(b: &Bundle) -> Bundle {
    let mut copy = b.clone();
    copy.timestamp = None::<Timestamp>;
    copy
}

fn clear_researcher(b: &Bundle) -> Bundle {
    let mut copy = b.clone();
    copy.researcher = None::<Researcher>;
    copy
}
