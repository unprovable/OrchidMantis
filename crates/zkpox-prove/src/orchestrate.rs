//! End-to-end orchestration. Wires `build`, `sp1-sdk`,
//! `zkpox-envelope`, and `zkpox-anchor` together.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde::Serialize;
use serde_bytes::ByteBuf;

use zkpox_anchor::{anchor_to_rekor, rekor_url};
use zkpox_backend_static_c::{
    PredicateSpec, TargetSpec, BACKEND_KIND, BACKEND_VERSION as STATIC_C_BACKEND_VERSION,
};
use zkpox_envelope::{seal_envelope, ENVELOPE_SCHEME};
use zkpox_predicates::outputs::{decode_crash_only, decode_oob_write};
use zkpox_schema::{
    sha256_bundle_pre_researcher, sha256_bundle_pre_timestamp, sha256_bytes, Bundle, BUNDLE_VERSION,
    ENVELOPE_NONE,
};

use crate::build::{build_or_load, resolve_guest_source, BuiltBackend};
use crate::cli::{BuildTargetArgs, ProveArgs, Wrap};

// --- build-target subcommand -------------------------------------------

#[derive(Serialize)]
struct BuildTargetReport<'a> {
    cache_key: &'a str,
    cache_dir: &'a str,
    elf_path: &'a str,
    target_hash: &'a str,
    predicate_id: &'a str,
    predicate_version: u32,
    vk_digest: &'a str,
    sp1_zkvm_version: &'a str,
    buf_size: usize,
}

pub fn cmd_build_target(args: BuildTargetArgs) -> Result<()> {
    let target = TargetSpec::new(&args.target).with_buf_size(args.buf_size);
    let predicate = PredicateSpec::from_id(&args.predicate);
    let guest_source = resolve_guest_source(args.guest_source.as_deref())?;
    let built = build_or_load(
        &target,
        &predicate,
        &guest_source,
        args.cache_dir.as_deref(),
        args.force,
    )?;

    if args.json {
        let report = BuildTargetReport {
            cache_key: &built.cache_key,
            cache_dir: built.cache_dir.to_str().unwrap_or(""),
            elf_path: built.elf_path.to_str().unwrap_or(""),
            target_hash: &built.target_hash_hex,
            predicate_id: &built.predicate_id,
            predicate_version: built.predicate_version,
            vk_digest: &built.vk_digest_hex,
            sp1_zkvm_version: &built.sp1_zkvm_version,
            buf_size: built.buf_size,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("cache_key:        {}", built.cache_key);
        println!("cache_dir:        {}", built.cache_dir.display());
        println!("elf:              {}", built.elf_path.display());
        println!("target_hash:      sha256:{}", built.target_hash_hex);
        println!(
            "predicate:        {} (canonical={:#010x} version={})",
            built.predicate_id, built.predicate_id_canonical, built.predicate_version
        );
        println!("verifier_key:    sha256:{}", built.vk_digest_hex);
        println!("sp1_zkvm:         {}", built.sp1_zkvm_version);
        println!("buf_size:         {}", built.buf_size);
    }
    Ok(())
}

// --- prove subcommand --------------------------------------------------

#[derive(Serialize)]
struct ProveReport {
    bundle: String,
    target_hash: String,
    predicate_id: String,
    backend: String,
    vk_digest: String,
    wrap: &'static str,
    proof_bytes: usize,
    envelope: bool,
    anchored: bool,
    researcher_signed: bool,
    rekor_log_index: Option<u64>,
}

pub fn cmd_prove(args: ProveArgs) -> Result<()> {
    // ---- Phase 1: ensure backend exists --------------------------------
    let target = TargetSpec::new(&args.target).with_buf_size(args.buf_size);
    let predicate = PredicateSpec::from_id(&args.predicate);
    let guest_source = resolve_guest_source(args.guest_source.as_deref())?;
    let backend = build_or_load(
        &target,
        &predicate,
        &guest_source,
        args.cache_dir.as_deref(),
        false,
    )?;

    // ---- Phase 2: drive SP1 --------------------------------------------
    let witness_bytes = std::fs::read(&args.witness)
        .with_context(|| format!("reading witness {:?}", args.witness))?;
    let (proof_bytes, public_values_bytes, pv) =
        run_sp1_prove(&backend, &witness_bytes, args.wrap)?;

    // ---- Phase 3: cross-check public values vs metadata ---------------
    cross_check_public_values(&pv, &backend, &predicate)?;
    if !pv.vuln_flag {
        bail!(
            "proof's public values say vuln_flag = false; the predicate did NOT observe the \
             violation for this witness. Refusing to write a bundle that does not assert exploitability."
        );
    }
    if pv.inv_flag {
        bail!(
            "proof's public values say inv_flag = true; the execution itself is invalid. \
             Refusing to bundle."
        );
    }

    // ---- Phase 4: optional envelope ------------------------------------
    // Resolve the vendor recipient: either supplied raw (--vendor-pubkey)
    // or fetched from the vendor's domain (--vendor-from-domain), in
    // which case we record its provenance in the bundle.
    let resolved_vendor = match (&args.vendor_pubkey, &args.vendor_from_domain) {
        (Some(pk), _) => Some(crate::vendor::ResolvedVendor::from_raw(pk.clone())),
        (None, Some(domain)) => {
            let rv = crate::vendor::resolve_from_domain(domain)
                .context("resolving vendor key from domain")?;
            tracing::info!(
                recipient = %rv.recipient,
                source = %rv.source_url.as_deref().unwrap_or(""),
                "resolved vendor age recipient from domain"
            );
            Some(rv)
        }
        (None, None) => None,
    };

    let envelope = match &resolved_vendor {
        Some(rv) => Some(
            seal_envelope(&witness_bytes, &rv.recipient, &args.tlock_duration)
                .context("sealing vendor envelope")?,
        ),
        None => None,
    };
    let resolved_vendor = resolved_vendor.unwrap_or_else(crate::vendor::ResolvedVendor::none);

    // ---- Phase 5: assemble bundle (pre-anchor, pre-researcher) ---------
    let target_hash_hex = backend.target_hash_hex.clone();
    let mut bundle = build_bundle(
        &backend,
        &predicate,
        &args,
        &proof_bytes,
        &public_values_bytes,
        &pv,
        envelope.as_ref(),
        &resolved_vendor,
        target_hash_hex.as_str(),
    )?;

    // ---- Phase 6: researcher signature (pre-anchor so signature   -----
    //              binds the bundle's content but not the timestamp).
    // A persistent, published identity is the default expectation. We
    // refuse to silently mint a throwaway key (its signature attests to
    // nothing); the caller must choose a persistent key, opt in to an
    // explicit ephemeral key for testing, or go anonymous.
    let researcher_signed = if args.anonymous {
        false
    } else {
        let kp = match (&args.researcher_key, args.ephemeral_researcher_key) {
            (Some(p), _) => load_researcher_key(p)?,
            (None, true) => {
                tracing::warn!(
                    "using an EPHEMERAL researcher key: the signature proves possession of a \
                     one-off key, not any persistent identity. For real disclosure pass \
                     --researcher-key <file> (+ --researcher-identity <url>)."
                );
                gen_ephemeral_researcher_key()
            }
            (None, false) => bail!(
                "no researcher key: pass --researcher-key <file> (a persistent ed25519 identity), \
                 or --ephemeral-researcher-key for a throwaway test key, or --anonymous to skip \
                 the researcher signature entirely."
            ),
        };
        attach_researcher_signature(&mut bundle, &kp, args.researcher_identity.as_deref())?;
        true
    };

    // ---- Phase 7: optional Rekor anchor --------------------------------
    let mut anchored = false;
    let mut rekor_log_index = None;
    if !args.no_anchor {
        let pre_ts = sha256_bundle_pre_timestamp(&bundle);
        let url = args.rekor_url.clone().unwrap_or_else(rekor_url);
        let anchor_kp = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let signature = ed25519_dalek::Signer::sign(&anchor_kp, &pre_ts);
        let pubkey_pem = ed25519_pubkey_pem(&anchor_kp.verifying_key());
        match anchor_to_rekor(&url, &pre_ts, &signature.to_bytes(), pubkey_pem.as_bytes()) {
            Ok((ts, _)) => {
                rekor_log_index = Some(ts.rekor_log_index);
                bundle.timestamp = Some(ts);
                anchored = true;
            }
            Err(e) => {
                tracing::warn!("rekor anchor failed: {e}. Continuing without anchor.");
            }
        }
    }

    // ---- Phase 8: write bundle ----------------------------------------
    let bundle_bytes = zkpox_schema::to_cbor(&bundle).context("CBOR-encoding bundle")?;
    std::fs::write(&args.output, &bundle_bytes)
        .with_context(|| format!("writing bundle to {:?}", args.output))?;

    let report = ProveReport {
        bundle: args.output.to_string_lossy().to_string(),
        target_hash: format!("sha256:{}", backend.target_hash_hex),
        predicate_id: backend.predicate_id.clone(),
        backend: format!("{}@{}", BACKEND_KIND, STATIC_C_BACKEND_VERSION),
        vk_digest: format!("sha256:{}", backend.vk_digest_hex),
        wrap: match args.wrap {
            Wrap::Core => "core",
            Wrap::Groth16 => "groth16",
        },
        proof_bytes: proof_bytes.len(),
        envelope: envelope.is_some(),
        anchored,
        researcher_signed,
        rekor_log_index,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

// --- Phase 2 helpers: SP1 driver ---------------------------------------

#[derive(Debug)]
pub(crate) struct ParsedPublicValues {
    pub version: u32,
    pub target_hash: [u8; 32],
    pub predicate_id: u32,
    pub predicate_version: u32,
    // Parsed to keep the public-values read order correct; the prover
    // binds the backend identity from its own BuiltBackend, so these
    // two are not read back here.
    #[allow(dead_code)]
    pub backend_id: u32,
    #[allow(dead_code)]
    pub backend_version: u32,
    pub inv_flag: bool,
    pub vuln_flag: bool,
    pub outputs_bytes: Vec<u8>,
}

fn run_sp1_prove(
    backend: &BuiltBackend,
    witness: &[u8],
    wrap: Wrap,
) -> Result<(Vec<u8>, Vec<u8>, ParsedPublicValues)> {
    use sp1_sdk::blocking::{ProveRequest as _, Prover as _, ProverClient};
    use sp1_sdk::{Elf, ProvingKey as _, SP1Stdin};

    if wrap == Wrap::Groth16 {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("tokio runtime for SP1 artifact install")?;
        rt.block_on(sp1_sdk::install::try_install_circuit_artifacts("groth16"))
            .context("installing SP1 groth16 circuit artifacts")?;
    }

    let elf_bytes = std::fs::read(&backend.elf_path)
        .with_context(|| format!("reading cached ELF {:?}", backend.elf_path))?;
    let elf: Elf = elf_bytes.into();

    let mut stdin = SP1Stdin::new();
    stdin.write(&witness.to_vec());

    let client = ProverClient::from_env();
    let pk = client
        .setup(elf)
        .map_err(|e| anyhow!("sp1 setup: {e}"))?;

    let proof = match wrap {
        Wrap::Core => client
            .prove(&pk, stdin)
            .run()
            .map_err(|e| anyhow!("sp1 prove (core) failed: {e}"))?,
        Wrap::Groth16 => client
            .prove(&pk, stdin)
            .groth16()
            .run()
            .map_err(|e| anyhow!("sp1 prove (groth16) failed: {e}"))?,
    };

    // In-process verify — refuse to bundle if the SDK can't verify
    // its own proof.
    client
        .verify(&proof, pk.verifying_key(), None)
        .map_err(|e| anyhow!("sp1-sdk refused to verify the proof in-process: {e}"))?;

    let proof_path = std::env::temp_dir().join(format!("zkpox-{}.proof", std::process::id()));
    proof
        .save(&proof_path)
        .map_err(|e| anyhow!("saving SP1 proof: {e}"))?;
    let proof_bytes = std::fs::read(&proof_path)?;
    let _ = std::fs::remove_file(&proof_path);

    let mut pv_clone = proof.public_values.clone();
    let parsed = parse_public_values(&mut pv_clone)?;
    let pv_bytes = proof.public_values.as_slice().to_vec();

    Ok((proof_bytes, pv_bytes, parsed))
}

/// Read the public values committed by the guest in the order
/// documented in `zkpox-schema::public_values`.
fn parse_public_values(pv: &mut sp1_sdk::SP1PublicValues) -> Result<ParsedPublicValues> {
    let version: u32 = pv.read::<u32>();
    let mut target_hash = [0u8; 32];
    for b in target_hash.iter_mut() {
        *b = pv.read::<u8>();
    }
    let predicate_id: u32 = pv.read::<u32>();
    let predicate_version: u32 = pv.read::<u32>();
    let backend_id: u32 = pv.read::<u32>();
    let backend_version: u32 = pv.read::<u32>();
    let flags: u32 = pv.read::<u32>();
    let outputs_len: u32 = pv.read::<u32>();
    let mut outputs_bytes = vec![0u8; outputs_len as usize];
    for b in outputs_bytes.iter_mut() {
        *b = pv.read::<u8>();
    }
    Ok(ParsedPublicValues {
        version,
        target_hash,
        predicate_id,
        predicate_version,
        backend_id,
        backend_version,
        inv_flag: flags & 0b01 != 0,
        vuln_flag: flags & 0b10 != 0,
        outputs_bytes,
    })
}

// --- Phase 3: cross-check ---------------------------------------------

fn cross_check_public_values(
    pv: &ParsedPublicValues,
    backend: &BuiltBackend,
    predicate: &PredicateSpec,
) -> Result<()> {
    if pv.version != zkpox_schema::PUBLIC_VALUES_VERSION {
        bail!(
            "proof public-values version {} does not match the schema version {} this prover \
             ships with — wire-breaking SP1 toolchain drift.",
            pv.version,
            zkpox_schema::PUBLIC_VALUES_VERSION,
        );
    }
    let expected_target_hash = hex::decode(&backend.target_hash_hex)?;
    if pv.target_hash[..] != expected_target_hash[..] {
        bail!(
            "proof's target_hash does not match the backend's bound target hash; the guest ELF \
             does not appear to have been built against this target source."
        );
    }
    if pv.predicate_id != predicate.id_canonical || pv.predicate_version != predicate.version {
        bail!(
            "proof predicate ({:#010x}@{}) disagrees with the requested predicate ({} @{:#010x}@{}).",
            pv.predicate_id,
            pv.predicate_version,
            predicate.id,
            predicate.id_canonical,
            predicate.version,
        );
    }
    Ok(())
}

// --- Phase 5: bundle assembly -----------------------------------------

fn build_bundle(
    backend: &BuiltBackend,
    predicate: &PredicateSpec,
    args: &ProveArgs,
    proof_bytes: &[u8],
    public_values_bytes: &[u8],
    pv: &ParsedPublicValues,
    envelope: Option<&zkpox_envelope::Envelope>,
    resolved_vendor: &crate::vendor::ResolvedVendor,
    target_hash_hex: &str,
) -> Result<Bundle> {
    use crate::cli::Wrap;
    use zkpox_schema::{
        Backend as SchemaBackend, Predicate as SchemaPredicate, Proof as SchemaProof,
        Target as SchemaTarget, VendorEnvelope,
    };

    let predicate_outputs = decode_outputs_for_predicate(&predicate.id, &pv.outputs_bytes);

    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert(
        "buf_size".to_string(),
        ciborium::Value::Integer((backend.buf_size as i64).into()),
    );
    metadata.insert(
        "entry_symbol".to_string(),
        ciborium::Value::Text("zkpox_victim".to_string()),
    );

    // Optional provenance: embed the supplied JSON object under a
    // `provenance` metadata key so the bundle records where the target
    // was extracted from (upstream repo, tag, fixed commit, function).
    if let Some(path) = &args.provenance {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading --provenance {:?}", path))?;
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).with_context(|| {
                format!("parsing --provenance {:?} as JSON", path)
            })?;
        metadata.insert("provenance".to_string(), json_to_ciborium(&json));
    }

    let target = SchemaTarget {
        kind: "c-source".to_string(),
        hash: format!("sha256:{}", target_hash_hex),
        url: args.target_url.clone(),
        source_url: args.source_url.clone(),
        metadata,
    };
    let predicate_field = SchemaPredicate {
        id: predicate.id.clone(),
        id_canonical: predicate.id_canonical,
        version: predicate.version,
        outputs: predicate_outputs,
    };
    let backend_field = SchemaBackend {
        kind: BACKEND_KIND.to_string(),
        id_canonical: zkpox_schema::registry::backend_id(BACKEND_KIND),
        version: STATIC_C_BACKEND_VERSION,
        verifier_key_digest: format!("sha256:{}", backend.vk_digest_hex),
    };
    let proof = SchemaProof {
        system: args.wrap.system_label().to_string(),
        bytes: ByteBuf::from(proof_bytes.to_vec()),
        public_values: ByteBuf::from(public_values_bytes.to_vec()),
        // For wrapped proofs (groth16), record the program vkey hash in
        // `vk.bytes32()` form so a verifier can run the lightweight
        // groth16 check without the guest ELF. It is the same 32 bytes
        // as `verifier_key_digest`, re-encoded as `0x`+hex. Omitted for
        // the core wrap, which is verified via the ELF anyway.
        sp1_vkey_hash: match args.wrap {
            Wrap::Groth16 => Some(format!("0x{}", backend.vk_digest_hex)),
            Wrap::Core => None,
        },
    };
    let vendor_envelope = match envelope {
        Some(env) => VendorEnvelope {
            scheme: ENVELOPE_SCHEME.to_string(),
            aes_blob: ByteBuf::from(env.aes_blob.clone()),
            ct_k_age: ByteBuf::from(env.ct_k_age.clone()),
            ct_k_tlock: ByteBuf::from(env.ct_k_tlock.clone()),
            drand_round_min: Some(env.drand_round),
            drand_target_round: Some(env.drand_round),
            drand_chain_hash: Some(hex::encode(zkpox_envelope::DRAND_QUICKNET_CHAIN_HASH)),
            vendor_pubkey: resolved_vendor.recipient.clone(),
            vendor_pubkey_fingerprint: sha256_bytes(resolved_vendor.recipient.as_bytes()),
            vendor_key_source_url: resolved_vendor.source_url.clone(),
            vendor_key_source_method: resolved_vendor.source_method.clone(),
        },
        None => VendorEnvelope {
            scheme: ENVELOPE_NONE.to_string(),
            aes_blob: ByteBuf::new(),
            ct_k_age: ByteBuf::new(),
            ct_k_tlock: ByteBuf::new(),
            drand_round_min: None,
            drand_target_round: None,
            drand_chain_hash: None,
            vendor_pubkey: String::new(),
            vendor_pubkey_fingerprint: sha256_bytes(b""),
            vendor_key_source_url: None,
            vendor_key_source_method: None,
        },
    };
    Ok(Bundle {
        version: BUNDLE_VERSION.to_string(),
        experimental: true,
        target,
        predicate: predicate_field,
        backend: backend_field,
        proof,
        vendor_envelope,
        timestamp: None,
        researcher: None,
    })
}

/// Convert a `serde_json::Value` into the `ciborium::Value` the bundle
/// metadata map stores. Lossless for the JSON subset provenance files
/// use (objects, arrays, strings, bools, integers, null); JSON numbers
/// with a fractional part fall back to `f64`.
fn json_to_ciborium(v: &serde_json::Value) -> ciborium::Value {
    use ciborium::Value as C;
    match v {
        serde_json::Value::Null => C::Null,
        serde_json::Value::Bool(b) => C::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                C::Integer(i.into())
            } else if let Some(u) = n.as_u64() {
                C::Integer(u.into())
            } else {
                C::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        serde_json::Value::String(s) => C::Text(s.clone()),
        serde_json::Value::Array(a) => C::Array(a.iter().map(json_to_ciborium).collect()),
        serde_json::Value::Object(o) => C::Map(
            o.iter()
                .map(|(k, val)| (C::Text(k.clone()), json_to_ciborium(val)))
                .collect(),
        ),
    }
}

/// Decode predicate-specific output bytes back into a CBOR Value for
/// the bundle's human-readable predicate.outputs section.
///
/// This is informational metadata only — the verifier validates by
/// matching `outputs_bytes` from the proof's public values against
/// what gets encoded back when the bundle is read.
fn decode_outputs_for_predicate(predicate_id: &str, bytes: &[u8]) -> ciborium::Value {
    use zkpox_backend_static_c::{PREDICATE_CRASH_ONLY, PREDICATE_MEMORY_SAFETY_OOB_WRITE};
    match predicate_id {
        PREDICATE_CRASH_ONLY => {
            if let Some(out) = decode_crash_only(bytes) {
                return ciborium::Value::Map(vec![(
                    ciborium::Value::Text("crashed".into()),
                    ciborium::Value::Bool(out.crashed),
                )]);
            }
        }
        PREDICATE_MEMORY_SAFETY_OOB_WRITE => {
            if let Some(out) = decode_oob_write(bytes) {
                return ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("count".into()),
                        ciborium::Value::Integer((out.count as i64).into()),
                    ),
                    (
                        ciborium::Value::Text("first_offset".into()),
                        ciborium::Value::Integer((out.first_offset as i64).into()),
                    ),
                ]);
            }
        }
        _ => {}
    }
    // Unknown predicate or undecodable bytes: surface as an opaque
    // byte string so the bundle is still parseable.
    ciborium::Value::Bytes(bytes.to_vec())
}

// --- Phase 6: researcher signature ------------------------------------

struct ResearcherKey {
    pem_pubkey: String,
    signer: ed25519_dalek::SigningKey,
}

fn load_researcher_key(p: &Path) -> Result<ResearcherKey> {
    let bytes = std::fs::read(p)?;
    if bytes.len() != 32 {
        bail!(
            "researcher key file must be exactly 32 raw bytes (got {})",
            bytes.len()
        );
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&bytes);
    let signer = ed25519_dalek::SigningKey::from_bytes(&sk);
    let pem_pubkey = ed25519_pubkey_pem(&signer.verifying_key());
    Ok(ResearcherKey { pem_pubkey, signer })
}

fn gen_ephemeral_researcher_key() -> ResearcherKey {
    let signer = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let pem_pubkey = ed25519_pubkey_pem(&signer.verifying_key());
    ResearcherKey { pem_pubkey, signer }
}

fn ed25519_pubkey_pem(vk: &ed25519_dalek::VerifyingKey) -> String {
    // Produce a SubjectPublicKeyInfo PEM via a minimal hand-rolled
    // ASN.1 wrapper. ed25519 SPKI is fixed-shape; the OID is
    // 1.3.101.112 and the SubjectPublicKey is the 32-byte raw key.
    let raw = vk.to_bytes();
    let mut der = Vec::with_capacity(64);
    der.extend_from_slice(&[0x30, 0x2A]); // SEQUENCE 0x2A
    der.extend_from_slice(&[0x30, 0x05]); //   SEQUENCE (alg id) 0x05
    der.extend_from_slice(&[0x06, 0x03, 0x2B, 0x65, 0x70]); //     OBJECT id-ed25519
    der.extend_from_slice(&[0x03, 0x21, 0x00]); //   BIT STRING (unused = 0)
    der.extend_from_slice(&raw);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

fn attach_researcher_signature(
    bundle: &mut Bundle,
    kp: &ResearcherKey,
    identity_url: Option<&str>,
) -> Result<()> {
    let digest = sha256_bundle_pre_researcher(bundle);
    let sig = ed25519_dalek::Signer::sign(&kp.signer, &digest);
    bundle.researcher = Some(zkpox_schema::Researcher {
        pubkey: ByteBuf::from(kp.pem_pubkey.clone().into_bytes()),
        signature_over_bundle: ByteBuf::from(sig.to_bytes().to_vec()),
        contact: None,
        identity_url: identity_url.map(|s| s.to_string()),
    });
    Ok(())
}
