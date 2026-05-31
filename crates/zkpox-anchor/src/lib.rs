//! # zkpox-anchor
//!
//! Sigstore Rekor anchor producer + verifier.
//!
//! Anchoring a bundle to Rekor commits `bundle_hash_pre_timestamp` to
//! an append-only public log. A verifier later checks both that
//! Rekor recorded that exact hash and that the log entry is included
//! in the published Merkle tree. The result: a tamper-evident
//! timestamp for the bundle without trusting a single notary.
//!
//! ## What this crate verifies
//!
//! Phase 1 of the standalone tool ships with two layers of check:
//!
//! 1. **Recorded-hash check** (the easy half). Fetch the entry from
//!    Rekor by log index; assert its `hashedrekord` body's
//!    `data.hash` equals `bundle_hash_pre_timestamp`.
//!
//! 2. **Merkle inclusion check** (the cryptographic half).
//!    Reconstruct the Rekor leaf from the entry body, walk up the
//!    Merkle path stored in the bundle, and check the resulting root
//!    matches `inclusion_proof_root_hash`. See [`check_inclusion_proof`].
//!
//! 3. **SET (Signed Entry Timestamp) check** (the endorsement half).
//!    When the operator hands us the log's public key, verify the
//!    Rekor v1 `signedEntryTimestamp` — the log's own signature over
//!    the canonical `{body, integratedTime, logIndex, logID}` JSON —
//!    against that key. The public `rekor.sigstore.dev` signs with
//!    ECDSA P-256; some self-hosted deployments use Ed25519; we
//!    dispatch on the PEM key type. See [`verify_set`] /
//!    [`check_set_signature`]. Without the SET check, the inclusion
//!    proof's authenticity rests on trusting the Rekor host we talked
//!    to; the SET removes that assumption — a lying log would have to
//!    forge its own signature.
//!
//! ## What this crate does NOT verify
//!
//! - The Rekor instance's identity. If you point us at a malicious
//!   private Rekor without supplying its public key, the anchor
//!   binding is only as good as that instance. Use the default
//!   `https://rekor.sigstore.dev` unless you have an explicit reason
//!   not to, and pass `--rekor-pubkey` to pin the trust anchor.
//! - The Sigstore root-of-trust. A later phase will integrate
//!   sigstore-rs for full TUF-rooted distribution of the log key; for
//!   now the operator supplies the log pubkey PEM they want to trust
//!   (the Rekor v2 witness-cosignature path lands with that work).

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use zkpox_schema::Bundle;

/// Default Sigstore Rekor URL. Override via `ZKPOX_REKOR_URL`.
pub const DEFAULT_REKOR_URL: &str = "https://rekor.sigstore.dev";

/// Errors from the anchor module.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("rekor request {0}")]
    Http(String),

    #[error("rekor returned {status}: {body}")]
    BadStatus { status: u16, body: String },

    #[error("rekor response missing field {0:?}")]
    Missing(&'static str),

    #[error("rekor response mis-shaped: {0}")]
    Shape(String),

    #[error("bundle has no timestamp to verify")]
    NoTimestamp,

    #[error("bundle hash mismatch: bundle hashes to {bundle:?}, Rekor recorded {rekor:?}")]
    HashMismatch { bundle: String, rekor: String },

    #[error("inclusion proof check failed at leaf={leaf:?}, expected_root={expected:?}, computed_root={computed:?}")]
    InclusionMismatch {
        leaf: String,
        expected: String,
        computed: String,
    },

    #[error("base64 decode of rekor body: {0}")]
    Base64(String),

    /// A malformed SET input — unparseable log pubkey PEM, unsupported
    /// key type, or a signature that doesn't even decode. Distinct
    /// from "the signature verified as invalid", which is `Ok(false)`
    /// from [`verify_set`]: that's the "log signed something else"
    /// case the caller must surface separately from a malformed proof.
    #[error("rekor SET signature: {0}")]
    SetSignature(String),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = core::result::Result<T, AnchorError>;

/// Resolve the Rekor URL, honouring the env var.
pub fn rekor_url() -> String {
    std::env::var("ZKPOX_REKOR_URL").unwrap_or_else(|_| DEFAULT_REKOR_URL.to_string())
}

/// The pinned public Sigstore Rekor v1 log signing key (ECDSA P-256),
/// vendored at `assets/rekor.pub`. Lets `zkpox-verify` check a bundle's
/// Signed Entry Timestamp on the happy path without a hand-supplied
/// `--rekor-pubkey`. The key is the one the Sigstore TUF root
/// distributes for `rekor.sigstore.dev`; see
/// `assets/rekor.pub.provenance.md` for the fingerprint and the
/// audit/refresh procedure (we pin rather than resolve TUF in-process to
/// keep the reproducible build image lean — `tough` would drag in a
/// cmake/aws-lc C build).
pub const DEFAULT_REKOR_PUBKEY_PEM: &str = include_str!("../assets/rekor.pub");

/// SPKI-DER sha256 of `DEFAULT_REKOR_PUBKEY_PEM`. A self-check guards
/// against the asset being edited without updating provenance.
pub const REKOR_PUBKEY_SHA256: &str =
    "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d";

/// The pinned Rekor log public key as PEM bytes, for the verifier's
/// default SET-check path. `None` is never returned today, but the
/// signature leaves room for a future "no pinned key" build.
pub fn default_rekor_pubkey_pem() -> &'static [u8] {
    DEFAULT_REKOR_PUBKEY_PEM.as_bytes()
}

// --- Rekor REST entry (the slice we use) -------------------------------

/// One Rekor log entry, parsed from the v1 REST shape. Rekor returns
/// a map keyed by entry UUID with a single value; this struct mirrors
/// that single value.
#[derive(Debug, Clone, Deserialize)]
pub struct RekorEntry {
    #[serde(rename = "logIndex")]
    pub log_index: u64,
    #[serde(rename = "logID")]
    pub log_id: String,
    #[serde(rename = "integratedTime")]
    pub integrated_time: i64,
    pub body: String, // base64-encoded JSON, see RekorBody below
    #[serde(default)]
    pub verification: Option<RekorVerification>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RekorVerification {
    #[serde(rename = "inclusionProof", default)]
    pub inclusion_proof: Option<RekorInclusionProof>,
    /// Rekor v1 Signed Entry Timestamp — base64 of the log's signature
    /// over the canonical entry payload. Absent on some self-hosted
    /// deployments; present on `rekor.sigstore.dev`.
    #[serde(rename = "signedEntryTimestamp", default)]
    pub signed_entry_timestamp: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RekorInclusionProof {
    #[serde(rename = "logIndex")]
    pub log_index: u64,
    #[serde(rename = "rootHash")]
    pub root_hash: String,
    #[serde(rename = "treeSize")]
    pub tree_size: u64,
    #[serde(default)]
    pub hashes: Vec<String>,
    #[serde(rename = "checkpoint", default)]
    pub checkpoint: Option<String>,
}

/// Decoded `body` of a Rekor entry. We only consume the slice
/// relevant to `hashedrekord/0.0.1`.
#[derive(Debug, Clone, Deserialize)]
pub struct RekorBody {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub spec: RekorBodySpec,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RekorBodySpec {
    pub data: RekorBodyData,
    pub signature: RekorBodySignature,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RekorBodyData {
    pub hash: RekorBodyHash,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RekorBodyHash {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RekorBodySignature {
    pub content: String,
    #[serde(rename = "publicKey")]
    pub public_key: RekorPublicKey,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RekorPublicKey {
    pub content: String,
}

// --- Anchor flow -------------------------------------------------------

/// hashedrekord proposed-entry body. Matches Rekor's 0.0.1 schema.
#[derive(Debug, Clone, Serialize)]
struct ProposedEntry {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    spec: ProposedSpec,
}

#[derive(Debug, Clone, Serialize)]
struct ProposedSpec {
    data: ProposedData,
    signature: ProposedSignature,
}

#[derive(Debug, Clone, Serialize)]
struct ProposedData {
    hash: ProposedHash,
}

#[derive(Debug, Clone, Serialize)]
struct ProposedHash {
    algorithm: &'static str,
    value: String, // hex of sha256
}

#[derive(Debug, Clone, Serialize)]
struct ProposedSignature {
    content: String, // base64
    #[serde(rename = "publicKey")]
    public_key: ProposedPublicKey,
}

#[derive(Debug, Clone, Serialize)]
struct ProposedPublicKey {
    content: String, // base64-encoded PEM
}

/// Anchor a bundle to Rekor.
///
/// `bundle_hash_pre_timestamp` is the canonical hash the caller has
/// already computed; we don't re-derive here so that the caller can
/// hold the bundle in a single canonical form throughout.
/// `signature_over_hash` is the caller's ed25519 signature over the
/// hash (32-byte digest). `pubkey_pem` is the SubjectPublicKeyInfo
/// PEM-encoded public key (Rekor's `hashedrekord/0.0.1` format
/// expects PEM).
pub fn anchor_to_rekor(
    rekor_url: &str,
    bundle_hash_pre_timestamp: &[u8; 32],
    signature_over_hash: &[u8],
    pubkey_pem: &[u8],
) -> Result<(zkpox_schema::Timestamp, RekorEntry)> {
    let proposed = ProposedEntry {
        api_version: "0.0.1",
        kind: "hashedrekord",
        spec: ProposedSpec {
            data: ProposedData {
                hash: ProposedHash {
                    algorithm: "sha256",
                    value: hex::encode(bundle_hash_pre_timestamp),
                },
            },
            signature: ProposedSignature {
                content: base64::engine::general_purpose::STANDARD.encode(signature_over_hash),
                public_key: ProposedPublicKey {
                    content: base64::engine::general_purpose::STANDARD.encode(pubkey_pem),
                },
            },
        },
    };

    let url = format!("{}/api/v1/log/entries", rekor_url.trim_end_matches('/'));
    let resp = ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_json(serde_json::to_value(&proposed)?);
    let resp = match resp {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            let body = r.into_string().unwrap_or_default();
            return Err(AnchorError::BadStatus { status: code, body });
        }
        Err(e) => return Err(AnchorError::Http(e.to_string())),
    };
    if resp.status() != 201 {
        let s = resp.status();
        let body = resp.into_string().unwrap_or_default();
        return Err(AnchorError::BadStatus { status: s, body });
    }

    let body_json: serde_json::Value = resp.into_json()?;
    let (uuid, entry) = parse_rekor_response(&body_json)?;
    let ts = build_timestamp(&uuid, &entry)?;
    Ok((ts, entry))
}

/// Fetch a log entry by index (the verifier's read path).
pub fn fetch_entry_by_index(rekor_url: &str, log_index: u64) -> Result<(String, RekorEntry)> {
    let url = format!(
        "{}/api/v1/log/entries?logIndex={}",
        rekor_url.trim_end_matches('/'),
        log_index
    );
    let resp = ureq::get(&url).call();
    let resp = match resp {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            let body = r.into_string().unwrap_or_default();
            return Err(AnchorError::BadStatus { status: code, body });
        }
        Err(e) => return Err(AnchorError::Http(e.to_string())),
    };
    let json: serde_json::Value = resp.into_json()?;
    parse_rekor_response(&json)
}

/// Pull `(uuid, entry)` out of a Rekor response.
fn parse_rekor_response(json: &serde_json::Value) -> Result<(String, RekorEntry)> {
    let map = json
        .as_object()
        .ok_or_else(|| AnchorError::Shape("response is not an object".into()))?;
    let (uuid, raw) = map
        .iter()
        .next()
        .ok_or_else(|| AnchorError::Shape("response object is empty".into()))?;
    let entry: RekorEntry = serde_json::from_value(raw.clone())?;
    Ok((uuid.clone(), entry))
}

fn build_timestamp(uuid: &str, entry: &RekorEntry) -> Result<zkpox_schema::Timestamp> {
    let v = entry
        .verification
        .as_ref()
        .ok_or(AnchorError::Missing("verification"))?;
    let inc = v
        .inclusion_proof
        .as_ref()
        .ok_or(AnchorError::Missing("verification.inclusionProof"))?;
    Ok(zkpox_schema::Timestamp {
        rekor_log_index: entry.log_index,
        rekor_log_id: entry.log_id.clone(),
        integrated_time: entry.integrated_time,
        entry_uuid: uuid.to_string(),
        inclusion_proof_root_hash: inc.root_hash.clone(),
        inclusion_proof_tree_size: inc.tree_size,
        inclusion_proof_hashes: inc.hashes.clone(),
        signed_entry_timestamp: v.signed_entry_timestamp.clone(),
    })
}

// --- Verification ------------------------------------------------------

/// Recorded-hash check: confirm Rekor's stored entry hash matches the
/// hash we computed from the bundle. This is the easy half of
/// anchor verification.
///
/// Caller passes `bundle_hash_pre_timestamp` (32-byte digest) — the
/// same value the producer signed when anchoring.
pub fn check_recorded_hash(
    bundle: &Bundle,
    bundle_hash_pre_timestamp: &[u8; 32],
    rekor_url: &str,
) -> Result<()> {
    let ts = bundle
        .timestamp
        .as_ref()
        .ok_or(AnchorError::NoTimestamp)?;
    let (_uuid, entry) = fetch_entry_by_index(rekor_url, ts.rekor_log_index)?;
    let body_bytes = base64::engine::general_purpose::STANDARD
        .decode(entry.body.as_bytes())
        .map_err(|e| AnchorError::Base64(e.to_string()))?;
    let body: RekorBody = serde_json::from_slice(&body_bytes)?;
    let want = hex::encode(bundle_hash_pre_timestamp);
    if body.spec.data.hash.value != want {
        return Err(AnchorError::HashMismatch {
            bundle: want,
            rekor: body.spec.data.hash.value,
        });
    }
    Ok(())
}

/// Local (no-network) Merkle inclusion proof check.
///
/// Given:
///   - the entry's body (base64-decoded; this is the bytes whose
///     sha256 forms the leaf, per Rekor's leaf-hash construction:
///     `sha256(0x00 || entry_body)`),
///   - the stored Merkle path (list of sibling hashes, hex-encoded),
///   - `tree_size` and `log_index`,
///   - the expected `root_hash` (hex-encoded),
///
/// reconstruct the root and assert it matches `root_hash`.
///
/// This is the Merkle Tree Hash defined by RFC 6962 §2 (which Rekor
/// follows): leaf nodes are prefixed with `0x00`, internal nodes with
/// `0x01`, then sha256'd.
pub fn check_inclusion_proof(
    entry_body_base64: &str,
    inclusion_proof_hashes: &[String],
    tree_size: u64,
    log_index: u64,
    expected_root_hex: &str,
) -> Result<()> {
    let body_bytes = base64::engine::general_purpose::STANDARD
        .decode(entry_body_base64.as_bytes())
        .map_err(|e| AnchorError::Base64(e.to_string()))?;

    // Leaf hash: sha256(0x00 || body_bytes)  per RFC 6962.
    let leaf = {
        let mut h = Sha256::new();
        h.update([0x00u8]);
        h.update(&body_bytes);
        h.finalize()
    };

    // Walk up the proof. The RFC 6962 "proof_at_index_n" verification
    // algorithm consumes one hash from the proof per level of the
    // tree, choosing left/right based on whether the current subtree
    // index is even (we're the left child) or the subtree spans
    // beyond size (we're the right child or this is the right-edge
    // case).
    let mut hash: [u8; 32] = leaf.into();
    let mut node = log_index;
    let mut last_node = tree_size.saturating_sub(1);
    let mut idx = 0;
    for sibling_hex in inclusion_proof_hashes {
        let sibling = hex_to_32(sibling_hex)
            .ok_or_else(|| AnchorError::Shape(format!("bad inclusion-proof hash: {sibling_hex:?}")))?;
        // Right-edge case: if `node` is the rightmost node in its
        // subtree (node == last_node) AND the sibling is at the same
        // level, the path doesn't fork — we just keep walking.
        if node == last_node && (node & 1) == 0 {
            // No sibling at this level; we are a left child without a
            // right partner. This shouldn't happen if Rekor's proof
            // includes only fork-points; defensive guard.
            return Err(AnchorError::Shape(format!(
                "inclusion proof contains hash at level {idx} where node has no sibling"
            )));
        }
        let combined = if node & 1 == 0 {
            // We are a left child: parent = hash(0x01 || self || sibling).
            internal_hash(&hash, &sibling)
        } else {
            // We are a right child: parent = hash(0x01 || sibling || self).
            internal_hash(&sibling, &hash)
        };
        hash = combined;
        node /= 2;
        last_node /= 2;
        idx += 1;
    }

    let expected = hex_to_32(expected_root_hex)
        .ok_or_else(|| AnchorError::Shape(format!("bad root hash: {expected_root_hex:?}")))?;
    if hash != expected {
        return Err(AnchorError::InclusionMismatch {
            leaf: hex::encode(leaf),
            expected: expected_root_hex.to_string(),
            computed: hex::encode(hash),
        });
    }
    Ok(())
}

/// RFC 6962 internal-node hash: sha256(0x01 || left || right).
fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    let v = hex::decode(s).ok()?;
    if v.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Some(out)
}

// --- SET (Signed Entry Timestamp) verification -------------------------
//
// Rekor v1 returns a `signedEntryTimestamp` (SET) inside each
// response's `verification` block: the log's own signature over a
// canonical JSON of the entry's `body` + `integratedTime` +
// `logIndex` + `logID`. The Merkle inclusion proof says "this leaf is
// in a tree with root R"; the SET says "the log *endorsed* this entry
// at this time." Together they rule out a Rekor instance lying about
// what its tree contains — to forge an entry it would have to forge
// the signature too.
//
// Rekor v2 carries the same intent via a signed checkpoint with
// witness cosignatures; that path lands with the Sigstore TUF
// integration that distributes the witness key set.

/// Read the hash Rekor recorded for an already-fetched entry — the
/// `spec.data.hash.value` of its `hashedrekord` body. Lets the
/// verifier perform the recorded-hash check, the inclusion check, and
/// the SET check from a single fetch rather than three round-trips.
pub fn entry_recorded_hash(entry: &RekorEntry) -> Result<String> {
    let body_bytes = base64::engine::general_purpose::STANDARD
        .decode(entry.body.as_bytes())
        .map_err(|e| AnchorError::Base64(e.to_string()))?;
    let body: RekorBody = serde_json::from_slice(&body_bytes)?;
    Ok(body.spec.data.hash.value)
}

/// Build the canonical JSON payload Rekor v1 signs for its SET.
///
/// Per the Sigstore Rekor v1 SET construction, the signed bytes are
/// the JSON object
///
/// ```text
/// {"body":<base64 entry body>,"integratedTime":<unix secs>,"logID":<hex>,"logIndex":<n>}
/// ```
///
/// with keys in lexicographic order and compact separators (no
/// whitespace) — exactly what Rekor's Go `jsoncanonicalizer` emits.
/// We build the string by hand in sorted key order rather than via a
/// serde map so the byte layout is independent of any
/// `serde_json/preserve_order` feature unification in the workspace.
/// A golden test pins the bytes against drift.
pub fn canonical_set_payload(
    entry_body_b64: &str,
    integrated_time: i64,
    log_index: u64,
    log_id: &str,
) -> Vec<u8> {
    // serde_json::to_string on a &str yields a correctly-quoted,
    // correctly-escaped JSON string literal (base64 `+`/`/`/`=` and
    // hex need no escaping, but this is robust regardless).
    let body = serde_json::to_string(entry_body_b64).expect("encode body string");
    let log = serde_json::to_string(log_id).expect("encode logID string");
    // Sorted keys: body < integratedTime < logID < logIndex.
    format!(
        "{{\"body\":{body},\"integratedTime\":{integrated_time},\"logID\":{log},\"logIndex\":{log_index}}}"
    )
    .into_bytes()
}

/// Verify a Rekor v1 SET signature against the operator-trusted log
/// public key.
///
/// Accepts both algorithm families Rekor v1 actually uses:
///   - **ECDSA P-256 / SHA-256** — the public `rekor.sigstore.dev`.
///     Rekor emits the signature ASN.1/DER-encoded; we try DER first,
///     then a fixed 64-byte `r || s` as a fallback.
///   - **Ed25519** — some self-hosted deployments / older keys.
///
/// The PEM key type drives the dispatch. Returns `Ok(true)` iff the
/// signature verifies, `Ok(false)` if it parses but verifies as
/// invalid (the "log signed something else" case), and
/// `Err(SetSignature)` on a malformed input (unparseable PEM,
/// unsupported key type, undecodable signature).
pub fn verify_set(
    canonical_payload: &[u8],
    signature: &[u8],
    log_pubkey_pem: &[u8],
) -> Result<bool> {
    let pem = std::str::from_utf8(log_pubkey_pem)
        .map_err(|e| AnchorError::SetSignature(format!("log pubkey PEM is not UTF-8: {e}")))?;

    // Ed25519 first — its SPKI is a fixed, unmistakable shape, so a
    // successful parse is unambiguous.
    {
        use ed25519_dalek::pkcs8::DecodePublicKey;
        use ed25519_dalek::Verifier;
        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_public_key_pem(pem) {
            let sig = ed25519_dalek::Signature::from_slice(signature).map_err(|e| {
                AnchorError::SetSignature(format!("ed25519 signature is not 64 bytes: {e}"))
            })?;
            return Ok(vk.verify(canonical_payload, &sig).is_ok());
        }
    }

    // ECDSA P-256 — the public Sigstore Rekor. Verification hashes the
    // payload with SHA-256 internally.
    {
        use p256::ecdsa::signature::Verifier;
        use p256::pkcs8::DecodePublicKey;
        if let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_pem(pem) {
            let sig = p256::ecdsa::Signature::from_der(signature)
                .or_else(|_| p256::ecdsa::Signature::from_slice(signature))
                .map_err(|e| {
                    AnchorError::SetSignature(format!("ECDSA P-256 signature parse: {e}"))
                })?;
            return Ok(vk.verify(canonical_payload, &sig).is_ok());
        }
    }

    Err(AnchorError::SetSignature(
        "unsupported log public key: PEM did not parse as Ed25519 or ECDSA P-256".to_string(),
    ))
}

/// End-to-end SET check for an already-fetched entry: rebuild the
/// canonical payload from the entry + the bundle's `Timestamp`,
/// base64-decode the entry's `signedEntryTimestamp`, and verify it
/// against `log_pubkey_pem`.
///
/// `Err(Missing)` if the operator asked for SET verification but the
/// log returned no SET; `Err(SetSignature)` on malformed inputs;
/// `Ok(false)` if the signature verifies as invalid; `Ok(true)` on
/// success.
pub fn check_set_signature(
    entry: &RekorEntry,
    ts: &zkpox_schema::Timestamp,
    log_pubkey_pem: &[u8],
) -> Result<bool> {
    let set_b64 = entry
        .verification
        .as_ref()
        .and_then(|v| v.signed_entry_timestamp.as_deref())
        .or(ts.signed_entry_timestamp.as_deref())
        .ok_or(AnchorError::Missing("verification.signedEntryTimestamp"))?;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(set_b64.as_bytes())
        .map_err(|e| AnchorError::SetSignature(format!("signedEntryTimestamp not base64: {e}")))?;
    let canonical = canonical_set_payload(
        &entry.body,
        ts.integrated_time,
        ts.rekor_log_index,
        &ts.rekor_log_id,
    );
    verify_set(&canonical, &sig, log_pubkey_pem)
}

// --- Tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned Rekor key must parse as an ECDSA P-256 SPKI, and the
    /// SPKI DER decoded from the PEM must hash to the recorded
    /// fingerprint — guards against the asset being edited without
    /// updating provenance / the const. We hash the DER recovered from
    /// the PEM body directly (matching `openssl pkey -pubin -outform
    /// DER`), avoiding an encode round-trip.
    #[test]
    fn pinned_rekor_key_matches_fingerprint() {
        use p256::pkcs8::DecodePublicKey;
        let pem = std::str::from_utf8(default_rekor_pubkey_pem()).unwrap();
        // Must parse as a real P-256 verifying key.
        p256::ecdsa::VerifyingKey::from_public_key_pem(pem)
            .expect("pinned rekor.pub must be a P-256 SPKI PEM");
        // DER = base64-decode of the PEM body between the framing lines.
        let der: Vec<u8> = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .flat_map(|l| {
                base64::engine::general_purpose::STANDARD
                    .decode(l.trim().as_bytes())
                    .expect("PEM body base64")
            })
            .collect();
        let fp = hex::encode(Sha256::digest(&der));
        assert_eq!(fp, REKOR_PUBKEY_SHA256, "pinned Rekor key fingerprint drift");
    }

    /// Build a tiny 4-leaf Merkle tree, prove inclusion of leaf 2,
    /// and verify the proof.
    #[test]
    fn rfc6962_inclusion_proof_round_trip() {
        // Four leaves L0..L3. Bodies are just dummy bytes.
        let bodies = [b"a", b"b", b"c", b"d"];
        let bodies_b64: Vec<String> = bodies
            .iter()
            .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
            .collect();
        let leaves: Vec<[u8; 32]> = bodies
            .iter()
            .map(|b| {
                let mut h = Sha256::new();
                h.update([0x00u8]);
                h.update(*b);
                h.finalize().into()
            })
            .collect();
        let i01 = internal_hash(&leaves[0], &leaves[1]);
        let i23 = internal_hash(&leaves[2], &leaves[3]);
        let root = internal_hash(&i01, &i23);

        // Prove L2 (index 2). Path: sibling L3, then sibling i01.
        let path = vec![hex::encode(leaves[3]), hex::encode(i01)];
        check_inclusion_proof(
            &bodies_b64[2],
            &path,
            4,        // tree_size
            2,        // log_index
            &hex::encode(root),
        )
        .expect("inclusion proof should verify");
    }

    /// Same tree, intentionally wrong root.
    #[test]
    fn inclusion_proof_fails_on_wrong_root() {
        let bodies = [b"a", b"b", b"c", b"d"];
        let bodies_b64: Vec<String> = bodies
            .iter()
            .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
            .collect();
        let leaves: Vec<[u8; 32]> = bodies
            .iter()
            .map(|b| {
                let mut h = Sha256::new();
                h.update([0x00u8]);
                h.update(*b);
                h.finalize().into()
            })
            .collect();
        let i01 = internal_hash(&leaves[0], &leaves[1]);

        let path = vec![hex::encode(leaves[3]), hex::encode(i01)];
        let res = check_inclusion_proof(
            &bodies_b64[2],
            &path,
            4,
            2,
            &"f".repeat(64), // wrong root
        );
        assert!(matches!(res, Err(AnchorError::InclusionMismatch { .. })));
    }

    // --- SET (Signed Entry Timestamp) ---------------------------------

    #[test]
    fn canonical_set_payload_is_sorted_and_compact() {
        // Golden vector. Keys MUST be lexicographically ordered
        // (body, integratedTime, logID, logIndex) with no whitespace —
        // byte-for-byte what Rekor's Go canonicalizer signs.
        let p = canonical_set_payload("Ym9keQ==", 1_700_000_000, 42, "abc123");
        assert_eq!(
            p,
            br#"{"body":"Ym9keQ==","integratedTime":1700000000,"logID":"abc123","logIndex":42}"#
                .to_vec(),
        );
    }

    #[test]
    fn verify_set_round_trip_ed25519() {
        use ed25519_dalek::pkcs8::EncodePublicKey;
        use ed25519_dalek::Signer;

        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pem = sk
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let payload = canonical_set_payload("Ym9keQ==", 1_700_000_000, 1, "logid");
        let sig = sk.sign(&payload);

        // Genuine signature verifies.
        assert!(verify_set(&payload, &sig.to_bytes(), pem.as_bytes()).unwrap());
        // Signature over a *different* payload verifies as invalid
        // (Ok(false), not Err — the log signed something else).
        let other = canonical_set_payload("Ym9keQ==", 1_700_000_001, 1, "logid");
        assert!(!verify_set(&other, &sig.to_bytes(), pem.as_bytes()).unwrap());
    }

    #[test]
    fn verify_set_round_trip_p256_der() {
        use p256::ecdsa::signature::Signer;
        use p256::pkcs8::EncodePublicKey;

        // ECDSA over P-256 is RFC-6979 deterministic, so a fixed key
        // gives a reproducible signature with no RNG.
        let sk = p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let pem = sk
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let payload = canonical_set_payload("Ym9keQ==", 1_700_000_000, 7, "logid");
        let sig: p256::ecdsa::Signature = sk.sign(&payload);
        let der = sig.to_der();

        // Rekor's wire form is DER-encoded.
        assert!(verify_set(&payload, der.as_bytes(), pem.as_bytes()).unwrap());
        // Wrong payload → invalid.
        let other = canonical_set_payload("Ym9keQ==", 999, 7, "logid");
        assert!(!verify_set(&other, der.as_bytes(), pem.as_bytes()).unwrap());
    }

    #[test]
    fn verify_set_rejects_garbage_pem() {
        let r = verify_set(b"payload", b"sig", b"-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n");
        assert!(matches!(r, Err(AnchorError::SetSignature(_))));
    }
}

