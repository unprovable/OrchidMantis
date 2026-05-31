//! The CBOR bundle types.
//!
//! This is the wire format for a zkpox disclosure bundle. Producers
//! build a `Bundle` by hand or via the higher-level `zkpox-prove`
//! orchestrator; verifiers decode bytes back into a `Bundle` and
//! validate every field.
//!
//! ## What is committed where
//!
//! - The SP1 STARK commits the **public values** (see
//!   `public_values.rs`). These are an integrity-bound projection of
//!   what the proof asserts.
//! - The bundle's `target`, `predicate`, `backend`, and `proof` fields
//!   are plaintext metadata. The verifier cross-checks each against
//!   the proof's public values: a bundle that lies about its target
//!   hash, predicate ID, or backend kind is detected when the proof's
//!   public values are decoded and compared.
//! - The bundle's `vendor_envelope` is structurally checked
//!   (fingerprints, scheme) but its decrypted contents are not — only
//!   the vendor or the post-tlock public can decrypt it. The proof
//!   already establishes that *some* witness made the predicate fire;
//!   the envelope merely says "and here is that witness, sealed."

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// Top-level bundle. The `version` field gates compatibility — see
/// `BUNDLE_VERSION`.
///
/// We deliberately do NOT derive `Eq` because nested CBOR `Value`
/// metadata (in `Target.metadata` and `Predicate.outputs`) doesn't
/// implement `Eq` due to floating-point variants. `PartialEq` is
/// enough for round-trip tests and field comparisons.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bundle {
    pub version: String,
    /// True for any bundle produced by a pre-stable release. The
    /// verifier emits a loud banner whenever this is true; consumers
    /// for real CVD should refuse `experimental == true`.
    pub experimental: bool,
    pub target: Target,
    pub predicate: Predicate,
    pub backend: Backend,
    pub proof: Proof,
    pub vendor_envelope: VendorEnvelope,
    /// Sigstore Rekor anchor. None if the producer skipped anchoring
    /// (e.g. `--no-anchor` for testing, or anchoring failed and
    /// `--require-anchor` was off).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub timestamp: Option<Timestamp>,
    /// Researcher attribution + signature. None for anonymous mode;
    /// priority is then established only by the Rekor timestamp.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub researcher: Option<Researcher>,
}

/// The program the exploit targets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Target {
    /// `c-source`, `elf-rv64im`, `llvm-ir`, etc. Bound to the backend
    /// kind (e.g. `static-c` backend takes `c-source` targets only).
    pub kind: String,
    /// `sha256:HEX` of the canonical target bytes (e.g. for C source,
    /// the file contents). Cross-checked against `PublicValues.target_hash`
    /// at verify time.
    pub hash: String,
    /// Optional URL where the target binary can be fetched.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub url: Option<String>,
    /// Optional URL for the target source (for c-source kind).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source_url: Option<String>,
    /// Free-form metadata: entry symbol, buffer size, compile flags,
    /// CVE identifiers if any. Not committed to the proof.
    #[serde(default)]
    pub metadata: std::collections::BTreeMap<String, ciborium::Value>,
}

/// The predicate the proof asserts fired.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Predicate {
    /// Human-readable identifier from `registry::PREDICATE_*`.
    pub id: String,
    /// Canonical u32 from `registry::predicate_id(id)`. Bundled
    /// alongside the string so a verifier doesn't have to reproduce
    /// the registry table to cross-check the proof's public values.
    pub id_canonical: u32,
    pub version: u32,
    /// Predicate-specific outputs decoded for human reading. Not
    /// committed independently; the canonical bytes live in the
    /// proof's public values, this is purely informational. Verifiers
    /// in `--strict` re-encode this and compare to the public values.
    pub outputs: ciborium::Value,
}

/// The backend that produced the proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backend {
    /// Human-readable identifier from `registry::BACKEND_*`.
    pub kind: String,
    pub id_canonical: u32,
    pub version: u32,
    /// The **real** SP1 verifying-key digest. NOT a sha256 of a
    /// literal placeholder string. The verifier checks this against
    /// the VK it computes from the backend's pinned ELF.
    pub verifier_key_digest: String,
}

/// The proof artefact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// e.g. `sp1-stark-core/v6.1.0`, `sp1-groth16-bn254/v6.1.0`.
    pub system: String,
    /// Exactly what `sp1-sdk`'s `proof.save(...)` produces — a
    /// length-prefixed serialised proof. The verifier feeds these
    /// bytes back into the SDK's `verify(...)` call.
    pub bytes: ByteBuf,
    /// SP1's public values, exposed separately so the verifier can
    /// render a human-readable summary without re-parsing the proof.
    /// Re-derived from `proof.bytes` at verify time and compared for
    /// equality; mismatch is a hard error.
    pub public_values: ByteBuf,
    /// The SP1 program verifying-key hash in `vk.bytes32()` form
    /// (`0x`-prefixed hex). Present for wrapped proofs (groth16/plonk)
    /// so the verifier can run the lightweight on-chain-style check
    /// (`sp1_verifier::Groth16Verifier`) without rebuilding the guest
    /// ELF. Cross-checked against `backend.verifier_key_digest`
    /// (`sha256` of the same 32 bytes) so it cannot lie. Older bundles
    /// and `core`-wrap proofs omit it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sp1_vkey_hash: Option<String>,
}

/// AES-256-GCM(witness, K) || age(K, vendor) || tlock(K, drand-future).
/// `scheme == ENVELOPE_NONE` if the producer chose not to seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorEnvelope {
    pub scheme: String,
    /// 12-byte nonce concatenated with AES-256-GCM ciphertext+tag.
    pub aes_blob: ByteBuf,
    /// age-encrypted symmetric key. Vendor decrypt path.
    pub ct_k_age: ByteBuf,
    /// tlock-encrypted symmetric key. Public-after-T decrypt path.
    pub ct_k_tlock: ByteBuf,
    /// Informational: earliest Drand round the tlock blob can decrypt.
    /// The blob itself binds the round cryptographically; this is for
    /// humans grepping the bundle.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub drand_round_min: Option<u64>,
    /// The exact Drand round the tlock blob is bound to — the round
    /// whose BLS signature decrypts `ct_k_tlock`. Distinct from
    /// `drand_round_min` (a floor); this is the concrete target the
    /// time-lock fires at. Set by the prover from the chosen duration.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub drand_target_round: Option<u64>,
    /// Hex (64 chars) of the Drand chain hash the `drand_target_round`
    /// refers to (e.g. quicknet `52db9ba7…`). Recorded so a verifier
    /// knows which Drand chain to pull the round signature from without
    /// assuming quicknet.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub drand_chain_hash: Option<String>,
    /// The vendor's age recipient string (`age1...`).
    pub vendor_pubkey: String,
    /// `sha256:HEX(vendor_pubkey)`. Trivially recomputable; bundled so
    /// verifiers don't have to know the SHA convention.
    pub vendor_pubkey_fingerprint: String,
    /// When the vendor key was resolved from a domain rather than passed
    /// in raw (`zkpox-prove --vendor-from-domain`), the URL it was
    /// fetched from (e.g. `https://vendor.example/.well-known/security.txt`).
    /// Lets a verifier trace the recipient back to a published source
    /// instead of trusting the producer's paste. None when supplied via
    /// `--vendor-pubkey`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vendor_key_source_url: Option<String>,
    /// How the vendor key was resolved at `vendor_key_source_url`:
    /// `"security.txt"` (a `Zkpox-Age-Recipient` field) or
    /// `"well-known-file"` (a dedicated `.well-known/zkpox-vendor.age.pub`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vendor_key_source_method: Option<String>,
}

/// Sigstore Rekor anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp {
    pub rekor_log_index: u64,
    pub rekor_log_id: String,
    pub integrated_time: i64,
    pub entry_uuid: String,
    pub inclusion_proof_root_hash: String,
    pub inclusion_proof_tree_size: u64,
    /// Merkle path from our entry up to the tree root, hex per node.
    /// Combined with `inclusion_proof_root_hash` and
    /// `inclusion_proof_tree_size`, lets a verifier reconstruct and
    /// check the path.
    pub inclusion_proof_hashes: Vec<String>,
    /// Rekor v1 **Signed Entry Timestamp** (SET): base64 of the log's
    /// own signature over the canonical
    /// `{body, integratedTime, logIndex, logID}` JSON. Optional —
    /// older bundles and some self-hosted logs omit it. When present
    /// and the verifier is handed the log's public key
    /// (`zkpox-verify --rekor-pubkey`), the SET proves the log itself
    /// endorsed this entry, closing the "a lying Rekor served us a
    /// consistent-but-fabricated tree" gap that the inclusion proof
    /// alone cannot.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signed_entry_timestamp: Option<String>,
}

/// Researcher attribution. None for anonymous disclosures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Researcher {
    /// Public key bytes (ed25519, SubjectPublicKeyInfo PEM or raw
    /// 32-byte format — let the verifier sniff).
    pub pubkey: ByteBuf,
    /// Signature over `sha256_bundle_pre_researcher(bundle)`.
    pub signature_over_bundle: ByteBuf,
    /// Optional contact (email, link, profile).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub contact: Option<String>,
    /// URL where the researcher's public key is published (e.g.
    /// `https://me.example/.well-known/zkpox-researcher.pub`). Binds
    /// the signing key to a persistent, published identity rather than
    /// an anonymous one-off key: a verifier (with `--online`) fetches
    /// this and confirms the published key matches `pubkey`. None for a
    /// bare key with no published identity.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identity_url: Option<String>,
}

// --- CBOR convenience ---------------------------------------------------

/// Encode a bundle as CBOR bytes. Uses ciborium with default settings;
/// callers needing the canonical form for hashing should use the
/// helpers in `hash.rs`.
pub fn to_cbor(bundle: &Bundle) -> crate::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(2048);
    ciborium::ser::into_writer(bundle, &mut buf)?;
    Ok(buf)
}

/// Decode a bundle from CBOR bytes. Does NOT enforce semantic
/// invariants beyond what serde sees; the high-level verifier does
/// the rest.
pub fn from_cbor(bytes: &[u8]) -> crate::Result<Bundle> {
    let b: Bundle = ciborium::de::from_reader(bytes)?;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sha256_bundle_pre_researcher, sha256_bundle_pre_timestamp, sha256_bytes, BUNDLE_VERSION,
        ENVELOPE_SCHEME,
    };

    fn fake_bundle() -> Bundle {
        Bundle {
            version: BUNDLE_VERSION.into(),
            experimental: true,
            target: Target {
                kind: "c-source".into(),
                hash: sha256_bytes(b"hello"),
                url: None,
                source_url: None,
                metadata: Default::default(),
            },
            predicate: Predicate {
                id: "memory-safety::oob-write".into(),
                id_canonical: 2,
                version: 1,
                outputs: ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("count".into()),
                        ciborium::Value::Integer(4i32.into()),
                    ),
                    (
                        ciborium::Value::Text("first_offset".into()),
                        ciborium::Value::Integer(16i32.into()),
                    ),
                ]),
            },
            backend: Backend {
                kind: "static-c".into(),
                id_canonical: 1,
                version: 1,
                verifier_key_digest: "sha256:".to_string() + &"a".repeat(64),
            },
            proof: Proof {
                system: "sp1-stark-core/v6.1.0".into(),
                bytes: ByteBuf::from(vec![1, 2, 3]),
                public_values: ByteBuf::from(vec![9, 9, 9]),
                sp1_vkey_hash: None,
            },
            vendor_envelope: VendorEnvelope {
                scheme: ENVELOPE_SCHEME.into(),
                aes_blob: ByteBuf::from(vec![0; 28]),
                ct_k_age: ByteBuf::from(vec![0; 64]),
                ct_k_tlock: ByteBuf::from(vec![0; 128]),
                drand_round_min: Some(12345),
                drand_target_round: Some(12345),
                drand_chain_hash: Some("52db9ba7".repeat(8)),
                vendor_pubkey: "age1qwerty".into(),
                vendor_pubkey_fingerprint: sha256_bytes(b"age1qwerty"),
                vendor_key_source_url: Some(
                    "https://vendor.example/.well-known/security.txt".into(),
                ),
                vendor_key_source_method: Some("security.txt".into()),
            },
            timestamp: None,
            researcher: None,
        }
    }

    #[test]
    fn cbor_round_trip() {
        let b = fake_bundle();
        let bytes = to_cbor(&b).unwrap();
        let decoded = from_cbor(&bytes).unwrap();
        assert_eq!(b, decoded);
    }

    /// Phase 4 — schema freeze guard. The on-wire format is frozen at
    /// `BUNDLE_VERSION`; any change to a struct's fields (add / remove /
    /// rename / reorder) must be a deliberate, version-bumped event, not
    /// a silent drift that invalidates already-published bundles.
    ///
    /// This pins three things that together make drift loud:
    ///   1. `BUNDLE_VERSION` is exactly `zkpox-2.0`.
    ///   2. Encoding is byte-stable (encode → decode → encode identical),
    ///      so the canonical bytes a bundle hashes/anchors over are
    ///      deterministic.
    ///   3. The exact CBOR map key sets of the top-level bundle and of
    ///      the trust-bearing sub-structs (`VendorEnvelope`, `Researcher`)
    ///      — `serde` emits a struct as a CBOR map keyed by field name, so
    ///      adding/removing/renaming a field changes this set and fails
    ///      the test. A reviewer who intends the change updates the
    ///      expected set here AND bumps `BUNDLE_VERSION`.
    #[test]
    fn schema_is_frozen_at_v2_0() {
        use ciborium::Value;

        // (1) Version pin.
        assert_eq!(
            BUNDLE_VERSION, "zkpox-2.0",
            "BUNDLE_VERSION changed — this is a wire-format break; bump deliberately and update \
             the freeze test + docs/BUNDLE-FORMAT.md"
        );

        // (2) Byte-stable round trip.
        let b = fake_bundle();
        let bytes = to_cbor(&b).unwrap();
        let reencoded = to_cbor(&from_cbor(&bytes).unwrap()).unwrap();
        assert_eq!(bytes, reencoded, "CBOR encoding is not byte-stable across a round trip");

        // (3) Frozen key sets. Decode to a generic CBOR Value and read
        // the map keys at each level. Nested fns (not closures) so they
        // can carry the lifetime on `get`.
        fn keys(v: &Value) -> Vec<String> {
            let mut ks: Vec<String> = match v {
                Value::Map(m) => m
                    .iter()
                    .filter_map(|(k, _)| match k {
                        Value::Text(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => panic!("expected a CBOR map"),
            };
            ks.sort();
            ks
        }
        fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
            match v {
                Value::Map(m) => m
                    .iter()
                    .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
                    .map(|(_, val)| val)
                    .unwrap_or_else(|| panic!("missing key {key:?}")),
                _ => panic!("expected a CBOR map"),
            }
        }
        let val: Value = ciborium::de::from_reader(&bytes[..]).unwrap();

        // Top-level (fake_bundle has no timestamp/researcher, both
        // skip_serializing_if=None, so they're absent here — that's the
        // frozen shape for a no-anchor, no-researcher bundle).
        assert_eq!(
            keys(&val),
            vec![
                "backend",
                "experimental",
                "predicate",
                "proof",
                "target",
                "vendor_envelope",
                "version",
            ],
            "top-level bundle key set changed"
        );

        // VendorEnvelope — the Phase-3 trust-source + Phase-3 drand fields
        // must stay frozen.
        assert_eq!(
            keys(get(&val, "vendor_envelope")),
            vec![
                "aes_blob",
                "ct_k_age",
                "ct_k_tlock",
                "drand_chain_hash",
                "drand_round_min",
                "drand_target_round",
                "scheme",
                "vendor_key_source_method",
                "vendor_key_source_url",
                "vendor_pubkey",
                "vendor_pubkey_fingerprint",
            ],
            "VendorEnvelope key set changed"
        );
    }

    #[test]
    fn pre_timestamp_hash_stable_across_adding_timestamp() {
        let b = fake_bundle();
        let h0 = sha256_bundle_pre_timestamp(&b);
        let with_ts = Bundle {
            timestamp: Some(Timestamp {
                rekor_log_index: 1,
                rekor_log_id: "x".into(),
                integrated_time: 1,
                entry_uuid: "u".into(),
                inclusion_proof_root_hash: "r".into(),
                inclusion_proof_tree_size: 1,
                inclusion_proof_hashes: vec![],
                signed_entry_timestamp: None,
            }),
            ..b
        };
        let h1 = sha256_bundle_pre_timestamp(&with_ts);
        // Adding a timestamp must NOT change the pre-timestamp hash —
        // that's the whole point of the anchor binding.
        assert_eq!(h0, h1);
    }

    #[test]
    fn pre_researcher_hash_stable_across_adding_researcher() {
        let b = fake_bundle();
        let h0 = sha256_bundle_pre_researcher(&b);
        let with_r = Bundle {
            researcher: Some(Researcher {
                pubkey: ByteBuf::from(vec![1; 32]),
                signature_over_bundle: ByteBuf::from(vec![2; 64]),
                contact: Some("me@example.com".into()),
                identity_url: Some("https://me.example/.well-known/zkpox-researcher.pub".into()),
            }),
            ..b
        };
        let h1 = sha256_bundle_pre_researcher(&with_r);
        assert_eq!(h0, h1);
    }
}
