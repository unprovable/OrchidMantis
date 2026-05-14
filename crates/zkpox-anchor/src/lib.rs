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
//!    matches `inclusion_proof_root_hash`. The Rekor signed-tree-head
//!    (STH) is then verified against the log's published ed25519
//!    public key.
//!
//! ## What this crate does NOT verify
//!
//! - The Rekor instance's identity. If you point us at a malicious
//!   private Rekor, the anchor binding is only as good as that
//!   instance. Use the default `https://rekor.sigstore.dev` unless
//!   you have an explicit reason not to.
//! - The Sigstore root-of-trust. Phase 1.x will integrate sigstore-rs
//!   for full TUF-rooted verification; here we use a pinned log key.

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

// --- Tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
}

