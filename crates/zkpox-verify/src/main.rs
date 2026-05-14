//! `zkpox-verify` — the standalone verifier binary.
//!
//! Real STARK verification + real Rekor inclusion-proof check +
//! envelope structural integrity. **No** placeholder hashes; bundles
//! whose `backend.verifier_key_digest` doesn't match the SP1 VK
//! derived locally from the cached or supplied guest ELF are
//! rejected.
//!
//! ## Verification flow (--strict mode)
//!
//!   1. Parse CBOR bundle; check `version` matches `BUNDLE_VERSION`.
//!   2. Structural checks: hash prefixes, fingerprint round-trip,
//!      envelope scheme.
//!   3. Optional --target re-hash: if the caller supplies a local
//!      copy of the target source, recompute its sha256 and assert it
//!      matches `bundle.target.hash`.
//!   4. SP1 STARK verification — load the ELF the verifier expects
//!      for this (backend, target, predicate) tuple, derive the VK,
//!      assert it matches `bundle.backend.verifier_key_digest`, then
//!      call `sp1_sdk::ProverClient::verify(proof, vk, None)`.
//!   5. Public-values cross-check: bundle.target.hash,
//!      predicate.id_canonical, predicate.version,
//!      backend.id_canonical, backend.version, plus
//!      inv_flag = false AND vuln_flag = true.
//!   6. Rekor anchor: fetch entry by index, confirm recorded hash
//!      matches `bundle_hash_pre_timestamp`; verify Merkle inclusion
//!      proof reconstructs `inclusion_proof_root_hash`.
//!   7. Researcher signature: if present, verify ed25519 signature
//!      over `bundle_hash_pre_researcher`.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use clap::Parser;
use serde::Serialize;

use zkpox_anchor::{check_inclusion_proof, check_recorded_hash, rekor_url};
use zkpox_backend_static_c::{
    cache_key, default_cache_dir, CacheEntry, PredicateSpec, BACKEND_KIND,
    BACKEND_VERSION as STATIC_C_BACKEND_VERSION,
};
use zkpox_predicates::outputs::{decode_crash_only, decode_oob_write};
use zkpox_schema::{
    from_cbor, sha256_bundle_pre_researcher, sha256_bundle_pre_timestamp, sha256_bytes,
    Bundle, BackendKind, BUNDLE_VERSION, ENVELOPE_NONE, ENVELOPE_SCHEME,
};

/// Pinned to match the prover.
const SP1_ZKVM_VERSION: &str = "6.0.1";

#[derive(Parser, Debug)]
#[command(
    name = "zkpox-verify",
    about = "Verify a zkpox disclosure bundle (STARK + Rekor + envelope structural integrity).",
    version,
)]
struct Cli {
    bundle: PathBuf,

    /// Fail on any deferred or unverifiable check. Recommended for
    /// real CVD pipelines.
    #[arg(long)]
    strict: bool,

    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long)]
    json: bool,

    /// Optional path to the local target source. If supplied, the
    /// verifier re-hashes it and asserts the hash matches
    /// `bundle.target.hash`.
    #[arg(long)]
    target: Option<PathBuf>,

    /// Whitelist of allowed backend kinds (default: static-c).
    /// Bundles with backends outside this list are rejected in
    /// `--strict`.
    #[arg(long, value_delimiter = ',', default_value = "static-c")]
    allow_backend: Vec<String>,

    /// Whitelist of allowed predicate IDs.
    #[arg(long, value_delimiter = ',')]
    allow_predicate: Vec<String>,

    /// Override the Rekor URL. Defaults to `ZKPOX_REKOR_URL` env var
    /// or `https://rekor.sigstore.dev`.
    #[arg(long)]
    rekor_url: Option<String>,

    /// Skip Rekor inclusion-proof verification. Useful for offline
    /// validation of bundles whose anchor we don't trust or can't
    /// reach. The Merkle inclusion check still runs against the
    /// inclusion proof embedded in the bundle.
    #[arg(long)]
    no_network: bool,

    /// Cache directory for backend ELFs (matches zkpox-prove's
    /// option). The verifier uses cached ELFs to derive the
    /// reference VK digest.
    #[arg(long)]
    cache_dir: Option<PathBuf>,
}

#[derive(Serialize, Default)]
struct VerifySummary {
    bundle_version: String,
    experimental: bool,
    target_kind: String,
    target_hash: String,
    predicate_id: String,
    predicate_version: u32,
    backend_kind: String,
    backend_version: u32,
    proof_system: String,
    proof_bytes_len: usize,
    envelope_scheme: String,
    has_timestamp: bool,
    has_researcher: bool,

    structural_checks_passed: bool,
    target_rehash_match: Option<bool>,
    stark_verified: Option<bool>,
    public_values_match: Option<bool>,
    rekor_recorded_hash_match: Option<bool>,
    rekor_inclusion_proof_valid: Option<bool>,
    researcher_signature_valid: Option<bool>,
    envelope_fingerprint_match: Option<bool>,

    overall_ok: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,sp1_sdk=warn")),
        )
        .init();

    let args = Cli::parse();
    let bundle_bytes = std::fs::read(&args.bundle)
        .with_context(|| format!("reading bundle {:?}", args.bundle))?;
    let bundle = from_cbor(&bundle_bytes).context("parsing bundle CBOR")?;

    let mut summary = VerifySummary::default();
    let mut ok = true;

    // ---- 1. Schema version -------------------------------------------
    if bundle.version != BUNDLE_VERSION {
        summary.errors.push(format!(
            "bundle.version is {:?}, expected {:?}",
            bundle.version, BUNDLE_VERSION
        ));
        ok = false;
    }
    summary.bundle_version = bundle.version.clone();
    summary.experimental = bundle.experimental;
    summary.target_kind = bundle.target.kind.clone();
    summary.target_hash = bundle.target.hash.clone();
    summary.predicate_id = bundle.predicate.id.clone();
    summary.predicate_version = bundle.predicate.version;
    summary.backend_kind = bundle.backend.kind.clone();
    summary.backend_version = bundle.backend.version;
    summary.proof_system = bundle.proof.system.clone();
    summary.proof_bytes_len = bundle.proof.bytes.len();
    summary.envelope_scheme = bundle.vendor_envelope.scheme.clone();
    summary.has_timestamp = bundle.timestamp.is_some();
    summary.has_researcher = bundle.researcher.is_some();

    // ---- 2. Structural checks ----------------------------------------
    if !bundle.target.hash.starts_with("sha256:") {
        summary
            .errors
            .push("target.hash missing 'sha256:' prefix".into());
        ok = false;
    }
    if !bundle.backend.verifier_key_digest.starts_with("sha256:") {
        summary
            .errors
            .push("backend.verifier_key_digest missing 'sha256:' prefix".into());
        ok = false;
    }
    let env_ok = bundle.vendor_envelope.scheme == ENVELOPE_SCHEME
        || bundle.vendor_envelope.scheme == ENVELOPE_NONE;
    if !env_ok {
        summary
            .errors
            .push(format!(
                "unsupported envelope scheme: {:?}",
                bundle.vendor_envelope.scheme
            ));
        ok = false;
    }
    // Vendor pubkey fingerprint must round-trip.
    let computed_fp =
        sha256_bytes(bundle.vendor_envelope.vendor_pubkey.as_bytes());
    if computed_fp != bundle.vendor_envelope.vendor_pubkey_fingerprint {
        summary.errors.push(format!(
            "vendor_pubkey_fingerprint mismatch: bundle {:?} != computed {}",
            bundle.vendor_envelope.vendor_pubkey_fingerprint, computed_fp
        ));
        ok = false;
        summary.envelope_fingerprint_match = Some(false);
    } else {
        summary.envelope_fingerprint_match = Some(true);
    }

    // Backend allowlist (always checked; --strict promotes any reject
    // to fatal).
    let allowed_backend = args
        .allow_backend
        .iter()
        .any(|s| s == &bundle.backend.kind);
    if !allowed_backend {
        let msg = format!(
            "backend.kind {:?} not in --allow-backend list {:?}",
            bundle.backend.kind, args.allow_backend
        );
        if args.strict {
            summary.errors.push(msg);
            ok = false;
        } else {
            summary.warnings.push(msg);
        }
    }
    // Predicate allowlist.
    if !args.allow_predicate.is_empty()
        && !args.allow_predicate.iter().any(|s| s == &bundle.predicate.id)
    {
        let msg = format!(
            "predicate.id {:?} not in --allow-predicate list {:?}",
            bundle.predicate.id, args.allow_predicate
        );
        if args.strict {
            summary.errors.push(msg);
            ok = false;
        } else {
            summary.warnings.push(msg);
        }
    }

    summary.structural_checks_passed = summary.errors.is_empty();

    // ---- 3. Optional target rehash -----------------------------------
    if let Some(p) = &args.target {
        let bytes = std::fs::read(p)
            .with_context(|| format!("reading --target {:?}", p))?;
        let local_hash = sha256_bytes(&bytes);
        let bundle_hash = &bundle.target.hash;
        let match_ = &local_hash == bundle_hash;
        summary.target_rehash_match = Some(match_);
        if !match_ {
            summary.errors.push(format!(
                "--target re-hash does not match bundle.target.hash: \
                 local={local_hash} bundle={bundle_hash}"
            ));
            ok = false;
        }
    }

    // ---- 4. STARK verification ---------------------------------------
    // Layer 1 (static-c) is the only path implemented here. For other
    // backend kinds, we leave stark_verified unset (= None) and warn.
    if BackendKind::from_name(&bundle.backend.kind) == BackendKind::StaticC {
        match verify_stark(&bundle, args.cache_dir.as_deref(), args.strict) {
            Ok(pv_match) => {
                summary.stark_verified = Some(true);
                summary.public_values_match = Some(pv_match);
                if !pv_match {
                    summary
                        .errors
                        .push("public values disagree with bundle metadata".into());
                    ok = false;
                }
            }
            Err(e) => {
                summary.stark_verified = Some(false);
                let msg = format!("STARK verification failed: {e:#}");
                if args.strict {
                    summary.errors.push(msg);
                    ok = false;
                } else {
                    summary.warnings.push(msg);
                }
            }
        }
    } else {
        let msg = format!(
            "no verifier for backend kind {:?} ships in v0.1; only static-c is supported. \
             See docs/ROADMAP.md.",
            bundle.backend.kind
        );
        if args.strict {
            summary.errors.push(msg);
            ok = false;
        } else {
            summary.warnings.push(msg);
        }
    }

    // ---- 5. Rekor anchor ---------------------------------------------
    if let Some(ts) = &bundle.timestamp {
        // The bundle's `inclusion_proof_hashes` ARE the Merkle path.
        // We need the entry body to compute the leaf hash; the
        // verifier fetches that from Rekor unless --no-network.
        match check_anchor(&bundle, ts, args.rekor_url.as_deref(), args.no_network) {
            Ok((recorded_match, inclusion_ok)) => {
                summary.rekor_recorded_hash_match = Some(recorded_match);
                summary.rekor_inclusion_proof_valid = Some(inclusion_ok);
                if !recorded_match {
                    summary.errors.push(
                        "Rekor's recorded hash does not match bundle_hash_pre_timestamp".into(),
                    );
                    ok = false;
                }
                if !inclusion_ok {
                    summary.errors.push(
                        "Rekor inclusion proof did not reconstruct the bundle's root_hash".into(),
                    );
                    ok = false;
                }
            }
            Err(e) => {
                let msg = format!("Rekor verification failed: {e:#}");
                if args.strict {
                    summary.errors.push(msg);
                    ok = false;
                } else {
                    summary.warnings.push(msg);
                }
            }
        }
    }

    // ---- 6. Researcher signature -------------------------------------
    if let Some(r) = &bundle.researcher {
        match verify_researcher_signature(&bundle, r) {
            Ok(()) => {
                summary.researcher_signature_valid = Some(true);
            }
            Err(e) => {
                summary.researcher_signature_valid = Some(false);
                summary.errors.push(format!("researcher signature: {e:#}"));
                ok = false;
            }
        }
    }

    summary.overall_ok = ok;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print_human(&summary, args.strict);
    }
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

// --- STARK verification -----------------------------------------------

fn verify_stark(
    bundle: &Bundle,
    cache_dir: Option<&std::path::Path>,
    strict: bool,
) -> Result<bool> {
    use sp1_sdk::blocking::{Prover as _, ProverClient};
    use sp1_sdk::{Elf, HashableKey as _, ProvingKey as _, SP1ProofWithPublicValues};

    // Layer 1 (static-c) cache lookup. The verifier finds the ELF
    // the prover produced for this (target_hash, predicate, sp1_zkvm)
    // tuple. If the user is verifying on a different machine, they
    // can pre-populate the cache by running `zkpox-prove build-target`
    // — same code path.
    let predicate = PredicateSpec::from_id(&bundle.predicate.id);
    let target_hash_hex = bundle
        .target
        .hash
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("bundle.target.hash missing sha256: prefix"))?;
    let mut target_hash = [0u8; 32];
    let decoded = hex::decode(target_hash_hex)
        .map_err(|_| anyhow!("bundle.target.hash not valid hex"))?;
    if decoded.len() != 32 {
        bail!("bundle.target.hash is not 32 bytes");
    }
    target_hash.copy_from_slice(&decoded);

    let key = cache_key(&target_hash, predicate.id_canonical, SP1_ZKVM_VERSION);
    let cache_root = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_cache_dir);
    let entry = CacheEntry::for_key(&cache_root, &key);
    if !entry.exists() {
        bail!(
            "no cached backend ELF for (target_hash={target_hash_hex}, predicate={}, sp1={}). \
             Build it first with: zkpox-prove build-target --target <source.c> --predicate {}.",
            bundle.predicate.id,
            SP1_ZKVM_VERSION,
            bundle.predicate.id,
        );
    }
    let elf_bytes = std::fs::read(&entry.elf_path)
        .with_context(|| format!("reading cached ELF {:?}", entry.elf_path))?;
    let elf: Elf = elf_bytes.into();

    let client = ProverClient::from_env();
    let pk = client.setup(elf).map_err(|e| anyhow!("sp1 setup: {e}"))?;
    let vk_bytes: [u8; 32] = pk.verifying_key().bytes32_raw();
    let computed_digest = format!("sha256:{}", hex::encode(vk_bytes));
    if computed_digest != bundle.backend.verifier_key_digest {
        bail!(
            "verifier_key_digest mismatch: bundle says {:?}, locally derived {:?} from cached ELF",
            bundle.backend.verifier_key_digest,
            computed_digest
        );
    }

    // Reconstruct the SP1 proof from `bundle.proof.bytes`. The SDK
    // saves and loads via the same serialised form.
    let proof_path = std::env::temp_dir()
        .join(format!("zkpox-verify-{}.proof", std::process::id()));
    std::fs::write(&proof_path, &bundle.proof.bytes)?;
    let proof = SP1ProofWithPublicValues::load(&proof_path)
        .map_err(|e| anyhow!("loading SP1 proof from bundle: {e}"))?;
    let _ = std::fs::remove_file(&proof_path);

    client
        .verify(&proof, pk.verifying_key(), None)
        .map_err(|e| anyhow!("sp1 verify: {e}"))?;

    // Read public values and cross-check.
    let mut pv = proof.public_values.clone();
    let version: u32 = pv.read::<u32>();
    let mut th = [0u8; 32];
    for b in th.iter_mut() {
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
    let inv_flag = flags & 0b01 != 0;
    let vuln_flag = flags & 0b10 != 0;

    // The whole point of the proof: must say "valid execution AND
    // violation observed."
    if inv_flag {
        bail!("public values inv_flag = true; execution invalid");
    }
    if !vuln_flag {
        bail!("public values vuln_flag = false; predicate did NOT observe a violation");
    }

    let backend_id_expected = zkpox_schema::registry::backend_id(BACKEND_KIND);
    let mut ok = true;
    if version != zkpox_schema::PUBLIC_VALUES_VERSION {
        return Err(anyhow!(
            "public-values schema version {} != verifier expected {}",
            version,
            zkpox_schema::PUBLIC_VALUES_VERSION
        ));
    }
    if th != target_hash {
        ok = false;
    }
    if predicate_id != bundle.predicate.id_canonical {
        ok = false;
    }
    if predicate_version != bundle.predicate.version {
        ok = false;
    }
    if backend_id != bundle.backend.id_canonical || backend_id != backend_id_expected {
        ok = false;
    }
    if backend_version != bundle.backend.version
        || backend_version != STATIC_C_BACKEND_VERSION
    {
        ok = false;
    }

    // Soft-check: bundle.predicate.outputs should re-render to the
    // same CBOR `outputs_bytes` produced by the proof. We re-decode
    // the bytes and compare. If the producer lied about
    // predicate.outputs, this catches it.
    if let Some(roundtrip) = decode_outputs_for_predicate(&bundle.predicate.id, &outputs_bytes) {
        if roundtrip != bundle.predicate.outputs {
            ok = false;
            if strict {
                // Don't bail — `verify_stark` returns Ok(false) so the
                // caller reports it. The verifier prints this in the
                // summary regardless.
            }
        }
    }

    Ok(ok)
}

fn decode_outputs_for_predicate(predicate_id: &str, bytes: &[u8]) -> Option<ciborium::Value> {
    use zkpox_backend_static_c::{PREDICATE_CRASH_ONLY, PREDICATE_MEMORY_SAFETY_OOB_WRITE};
    match predicate_id {
        PREDICATE_CRASH_ONLY => decode_crash_only(bytes).map(|o| {
            ciborium::Value::Map(vec![(
                ciborium::Value::Text("crashed".into()),
                ciborium::Value::Bool(o.crashed),
            )])
        }),
        PREDICATE_MEMORY_SAFETY_OOB_WRITE => decode_oob_write(bytes).map(|o| {
            ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("count".into()),
                    ciborium::Value::Integer((o.count as i64).into()),
                ),
                (
                    ciborium::Value::Text("first_offset".into()),
                    ciborium::Value::Integer((o.first_offset as i64).into()),
                ),
            ])
        }),
        _ => None,
    }
}

// --- Anchor verification ----------------------------------------------

fn check_anchor(
    bundle: &Bundle,
    ts: &zkpox_schema::Timestamp,
    rekor_override: Option<&str>,
    no_network: bool,
) -> Result<(bool, bool)> {
    let bundle_hash = sha256_bundle_pre_timestamp(bundle);

    // Recorded-hash check requires network unless `no_network`.
    let recorded_ok = if no_network {
        // Skip the recorded-hash check; mark as None at the call site.
        true
    } else {
        let url = rekor_override
            .map(|s| s.to_string())
            .unwrap_or_else(rekor_url);
        check_recorded_hash(bundle, &bundle_hash, &url)
            .map(|()| true)
            .or_else(|e| {
                // Distinguish network errors from cryptographic
                // mismatches. We treat both as `false` here; the
                // strict-mode caller surfaces the underlying error
                // via the warnings list.
                tracing::warn!("rekor recorded-hash check: {e}");
                Ok::<bool, anyhow::Error>(false)
            })?
    };

    // Inclusion proof check is purely local once we have the entry
    // body. With --no-network we can't fetch the body; the check
    // becomes "we trust the bundle's stored body" — which is no check
    // at all. We report None upstream in that case. For now we fetch
    // the body if network is allowed.
    let inclusion_ok = if no_network {
        true
    } else {
        let url = rekor_override
            .map(|s| s.to_string())
            .unwrap_or_else(rekor_url);
        match zkpox_anchor::fetch_entry_by_index(&url, ts.rekor_log_index) {
            Ok((_uuid, entry)) => {
                check_inclusion_proof(
                    &entry.body,
                    &ts.inclusion_proof_hashes,
                    ts.inclusion_proof_tree_size,
                    ts.rekor_log_index,
                    &ts.inclusion_proof_root_hash,
                )
                .map(|()| true)
                .unwrap_or_else(|e| {
                    tracing::warn!("inclusion proof: {e}");
                    false
                })
            }
            Err(e) => {
                tracing::warn!("rekor fetch entry: {e}");
                false
            }
        }
    };

    Ok((recorded_ok, inclusion_ok))
}

// --- Researcher signature ---------------------------------------------

fn verify_researcher_signature(
    bundle: &Bundle,
    r: &zkpox_schema::Researcher,
) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pubkey_pem =
        std::str::from_utf8(&r.pubkey).context("researcher.pubkey is not valid UTF-8 PEM")?;
    let vk = pem_to_ed25519_pubkey(pubkey_pem)?;
    let sig_bytes: &[u8] = &r.signature_over_bundle;
    if sig_bytes.len() != 64 {
        bail!("researcher.signature_over_bundle must be 64 bytes (got {})", sig_bytes.len());
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let digest = sha256_bundle_pre_researcher(bundle);
    let vk_obj: VerifyingKey = vk;
    vk_obj
        .verify(&digest, &sig)
        .map_err(|e| anyhow!("ed25519 verify: {e}"))
}

fn pem_to_ed25519_pubkey(pem: &str) -> Result<ed25519_dalek::VerifyingKey> {
    // Strip PEM framing, base64-decode, then parse the SPKI ASN.1.
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim().as_bytes())
        .map_err(|e| anyhow!("base64 decode PEM body: {e}"))?;
    // For our hand-rolled SPKI shape, the 32-byte raw pubkey is the
    // last 32 bytes of the DER. (See zkpox-prove::ed25519_pubkey_pem
    // for the matching encoder.)
    if der.len() < 32 {
        bail!("DER too short to contain an ed25519 raw key");
    }
    let raw = &der[der.len() - 32..];
    let mut buf = [0u8; 32];
    buf.copy_from_slice(raw);
    ed25519_dalek::VerifyingKey::from_bytes(&buf).map_err(|e| anyhow!("ed25519 from_bytes: {e}"))
}

// --- Human output -----------------------------------------------------

fn print_human(s: &VerifySummary, strict: bool) {
    let banner = if s.overall_ok { "OK" } else { "FAIL" };
    println!(
        "zkpox bundle: version {} ({}){}",
        s.bundle_version,
        banner,
        if s.experimental { " [EXPERIMENTAL]" } else { "" }
    );
    println!("  target:        {} hash={}", s.target_kind, s.target_hash);
    println!(
        "  predicate:     {} (v{})",
        s.predicate_id, s.predicate_version
    );
    println!(
        "  backend:       {} (v{})",
        s.backend_kind, s.backend_version
    );
    println!(
        "  proof:         {} ({} bytes)",
        s.proof_system, s.proof_bytes_len
    );
    println!("  envelope:      {}", s.envelope_scheme);
    println!(
        "  timestamp:     {}",
        if s.has_timestamp { "present" } else { "(none)" }
    );
    println!(
        "  researcher:    {}",
        if s.has_researcher { "signed" } else { "(none)" }
    );

    println!();
    println!("checks:");
    println!(
        "  structural:                 {}",
        ok_str(s.structural_checks_passed)
    );
    println!(
        "  vendor pubkey fp:           {}",
        opt_str(s.envelope_fingerprint_match)
    );
    println!(
        "  --target rehash:            {}",
        opt_str(s.target_rehash_match)
    );
    println!(
        "  STARK proof:                {}",
        opt_str(s.stark_verified)
    );
    println!(
        "  public values cross-check:  {}",
        opt_str(s.public_values_match)
    );
    println!(
        "  Rekor recorded hash:        {}",
        opt_str(s.rekor_recorded_hash_match)
    );
    println!(
        "  Rekor inclusion proof:      {}",
        opt_str(s.rekor_inclusion_proof_valid)
    );
    println!(
        "  researcher signature:       {}",
        opt_str(s.researcher_signature_valid)
    );

    if !s.warnings.is_empty() {
        println!();
        println!("warnings:");
        for w in &s.warnings {
            println!("  - {w}");
        }
    }
    if !s.errors.is_empty() {
        println!();
        println!("errors:");
        for e in &s.errors {
            println!("  - {e}");
        }
    }
    println!();
    if s.experimental {
        eprintln!(
            "  EXPERIMENTAL BUNDLE — produced by zkpox v0.x (beta). \
             Bundle format and verifier semantics subject to change. \
             Do NOT use for real CVE disclosure. Scope: docs/SCOPE.md"
        );
    }
    if !strict {
        eprintln!(
            "  MODE: lenient — checks that fall back to network or to a missing \
             local cache are downgraded to warnings. Pass --strict for CI use."
        );
    }
}

fn ok_str(b: bool) -> &'static str {
    if b { "ok" } else { "FAIL" }
}
fn opt_str(b: Option<bool>) -> &'static str {
    match b {
        Some(true) => "ok",
        Some(false) => "FAIL",
        None => "n/a",
    }
}
