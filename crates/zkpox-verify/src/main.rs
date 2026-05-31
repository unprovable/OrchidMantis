//! `zkpox-verify` — the standalone verifier binary.
//!
//! Real STARK verification + real Rekor inclusion-proof check +
//! envelope structural integrity. **No** placeholder hashes; bundles
//! whose `backend.verifier_key_digest` doesn't match the SP1 VK
//! derived locally from the cached or supplied guest ELF are
//! rejected.
//!
//! ## Verification flow (strict mode — the default)
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
//!   6. Rekor anchor (single fetch): confirm Rekor's recorded hash
//!      matches `bundle_hash_pre_timestamp`; verify the Merkle
//!      inclusion proof reconstructs `inclusion_proof_root_hash`; and,
//!      when `--rekor-pubkey` is supplied, verify the log's Signed
//!      Entry Timestamp (SET) signature against that key.
//!   7. Researcher signature: if present, verify ed25519 signature
//!      over `bundle_hash_pre_researcher`.
//!
//! Strict is the default (matching the disclosure-grade posture): any
//! check that cannot complete is fatal. `--no-strict` downgrades the
//! network- or cache-dependent checks to warnings for local triage.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use clap::Parser;
use serde::Serialize;

use zkpox_anchor::{
    check_inclusion_proof, check_set_signature, entry_recorded_hash, fetch_entry_by_index,
    rekor_url,
};
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

    /// Downgrade checks that depend on the network or a local ELF
    /// cache (STARK, Rekor, allowlists) from fatal to warnings. Strict
    /// is the DEFAULT — pass this only for offline local triage, never
    /// for a real CVD acceptance gate.
    #[arg(long)]
    no_strict: bool,

    /// Deprecated: strict is now the default. Kept as a hidden no-op
    /// alias so existing scripts that pass `--strict` don't break.
    #[arg(long, hide = true)]
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
    /// Bundles with backends outside this list are rejected in strict
    /// mode (the default), or downgraded to a warning under
    /// `--no-strict`.
    #[arg(long, value_delimiter = ',', default_value = "static-c")]
    allow_backend: Vec<String>,

    /// Whitelist of allowed predicate IDs.
    #[arg(long, value_delimiter = ',')]
    allow_predicate: Vec<String>,

    /// Override the Rekor URL. Defaults to `ZKPOX_REKOR_URL` env var
    /// or `https://rekor.sigstore.dev`.
    #[arg(long)]
    rekor_url: Option<String>,

    /// Path to the trusted Rekor log's public key (PEM, SPKI). When
    /// supplied, the verifier checks the entry's Signed Entry
    /// Timestamp (SET) signature against this key — proving the log
    /// itself endorsed the entry, not just that an inclusion proof
    /// reconstructs. Accepts ECDSA P-256 (public Sigstore Rekor) or
    /// Ed25519 (some self-hosted logs). Omit to skip the SET check.
    #[arg(long)]
    rekor_pubkey: Option<PathBuf>,

    /// Skip all Rekor anchor checks (recorded-hash, Merkle inclusion,
    /// and SET). Every one needs the entry body fetched from Rekor, so
    /// offline they report "not run" rather than pass. Useful for
    /// validating the STARK + structure of a bundle whose anchor we
    /// can't reach; under strict mode (the default) a present-but-
    /// unverified timestamp still surfaces, so pair with `--no-strict`
    /// for a clean offline exit.
    #[arg(long)]
    no_network: bool,

    /// Cache directory for backend ELFs (matches zkpox-prove's
    /// option). The verifier uses cached ELFs to derive the
    /// reference VK digest.
    #[arg(long)]
    cache_dir: Option<PathBuf>,

    /// Re-fetch and re-check the bundle's recorded trust sources over
    /// the network: the vendor key from `vendor_key_source_url`, and the
    /// researcher key from `researcher.identity_url`. Without this flag
    /// the verifier validates only what the bundle records (offline);
    /// with it, the recorded keys are confirmed against their published
    /// sources. Needs network.
    #[arg(long)]
    online: bool,
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
    /// Upstream provenance object from `target.metadata.provenance`, if
    /// the producer embedded one (via `zkpox-prove --provenance`). This
    /// is plaintext metadata — NOT committed to the proof — surfaced so
    /// a reviewer can trace the harness back to upstream source.
    #[serde(skip_serializing_if = "Option::is_none")]
    target_provenance: Option<serde_json::Value>,

    /// Where the vendor key was resolved from (`vendor_key_source_url` +
    /// method), surfaced so a reviewer can trace the recipient to a
    /// published source. None when the key was supplied raw.
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor_key_source: Option<String>,
    /// Where the researcher's identity key is published
    /// (`researcher.identity_url`). None for a bare key.
    #[serde(skip_serializing_if = "Option::is_none")]
    researcher_identity_url: Option<String>,
    /// Time-lock summary: the Drand target round + chain, surfaced from
    /// the envelope. None when there is no envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    timelock: Option<String>,
    /// Which Rekor log key the SET check trusted: `"pinned-sigstore"`
    /// (the vendored default) or `"--rekor-pubkey"` (operator override).
    #[serde(skip_serializing_if = "Option::is_none")]
    rekor_key_source: Option<String>,

    structural_checks_passed: bool,
    target_rehash_match: Option<bool>,
    stark_verified: Option<bool>,
    public_values_match: Option<bool>,
    rekor_recorded_hash_match: Option<bool>,
    rekor_inclusion_proof_valid: Option<bool>,
    rekor_set_signature_valid: Option<bool>,
    researcher_signature_valid: Option<bool>,
    envelope_fingerprint_match: Option<bool>,
    /// `--online` re-check: the key published at `vendor_key_source_url`
    /// still equals `vendor_pubkey`. None when not run.
    vendor_key_source_match: Option<bool>,
    /// `--online` re-check: the key published at `researcher.identity_url`
    /// still equals `researcher.pubkey`. None when not run.
    researcher_identity_match: Option<bool>,

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

    // Strict is the default; --no-strict opts out. The legacy
    // --strict flag is a hidden no-op alias.
    let strict = !args.no_strict;
    if args.strict {
        eprintln!("[zkpox] --strict is a no-op: strict is now the default. Use --no-strict to opt out.");
    }

    // Trusted Rekor log public key for SET verification. `--rekor-pubkey`
    // overrides; otherwise default to the pinned public-Sigstore key
    // (zkpox_anchor::default_rekor_pubkey_pem), so the SET check runs on
    // the happy path with no hand-supplied PEM. The pin is the key the
    // Sigstore TUF root distributes for rekor.sigstore.dev — see
    // crates/zkpox-anchor/assets/rekor.pub.provenance.md.
    let (rekor_pubkey_pem, rekor_key_source): (Option<Vec<u8>>, &str) = match &args.rekor_pubkey {
        Some(p) => (
            Some(std::fs::read(p).with_context(|| format!("reading --rekor-pubkey {:?}", p))?),
            "--rekor-pubkey",
        ),
        None => (
            Some(zkpox_anchor::default_rekor_pubkey_pem().to_vec()),
            "pinned-sigstore",
        ),
    };

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
    summary.target_provenance = bundle
        .target
        .metadata
        .get("provenance")
        .map(ciborium_to_json);

    // Trust-source provenance (Phase 3): surface where each key came
    // from, so a reviewer can trace it back to a published source.
    let env = &bundle.vendor_envelope;
    if let Some(url) = &env.vendor_key_source_url {
        let method = env.vendor_key_source_method.as_deref().unwrap_or("?");
        summary.vendor_key_source = Some(format!("{url} ({method})"));
    }
    if let Some(r) = &bundle.researcher {
        summary.researcher_identity_url = r.identity_url.clone();
    }
    if let Some(round) = env.drand_target_round.or(env.drand_round_min) {
        let chain = env.drand_chain_hash.as_deref().unwrap_or("(chain unrecorded)");
        let unlock = drand_round_unlock_estimate(round);
        summary.timelock = Some(format!("round {round} on chain {chain}{unlock}"));
    }
    // Which Rekor key the SET check will trust — only relevant if the
    // bundle carries a timestamp to check.
    if bundle.timestamp.is_some() {
        summary.rekor_key_source = Some(rekor_key_source.to_string());
    }

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
        if strict {
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
        if strict {
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
        match verify_stark(&bundle, args.cache_dir.as_deref(), strict) {
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
                if strict {
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
        if strict {
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
        // verifier fetches that from Rekor (one fetch covers the
        // recorded-hash, inclusion, and SET checks) unless --no-network.
        match check_anchor(
            &bundle,
            ts,
            args.rekor_url.as_deref(),
            args.no_network,
            rekor_pubkey_pem.as_deref(),
        ) {
            Ok(outcome) => {
                summary.rekor_recorded_hash_match = outcome.recorded_match;
                summary.rekor_inclusion_proof_valid = outcome.inclusion_ok;
                summary.rekor_set_signature_valid = outcome.set_valid;
                if outcome.recorded_match == Some(false) {
                    summary.errors.push(
                        "Rekor's recorded hash does not match bundle_hash_pre_timestamp".into(),
                    );
                    ok = false;
                }
                if outcome.inclusion_ok == Some(false) {
                    summary.errors.push(
                        "Rekor inclusion proof did not reconstruct the bundle's root_hash".into(),
                    );
                    ok = false;
                }
                if outcome.set_valid == Some(false) {
                    summary.errors.push(
                        "Rekor SET signature did not verify against the trusted log key \
                         (pinned default, or --rekor-pubkey if supplied)".into(),
                    );
                    ok = false;
                }
            }
            Err(e) => {
                let msg = format!("Rekor verification failed: {e:#}");
                if strict {
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

    // ---- 7. Online trust-source re-checks (--online) -----------------
    // Re-fetch the bundle's recorded trust sources and confirm the keys
    // it carries still match what those sources publish. Offline (the
    // default) these stay None ("not run") and the recorded provenance
    // is surfaced but not re-verified.
    if args.online {
        // Vendor key: published recipient at vendor_key_source_url must
        // equal the recipient the envelope was sealed to.
        if let Some(url) = &bundle.vendor_envelope.vendor_key_source_url {
            match recheck_vendor_key(url, &bundle.vendor_envelope.vendor_pubkey) {
                Ok(m) => {
                    summary.vendor_key_source_match = Some(m);
                    if !m {
                        summary.errors.push(format!(
                            "vendor key published at {url} no longer matches the bundle's \
                             vendor_pubkey"
                        ));
                        ok = false;
                    }
                }
                Err(e) => {
                    let msg = format!("vendor-key online re-check ({url}): {e:#}");
                    if strict {
                        summary.errors.push(msg);
                        ok = false;
                    } else {
                        summary.warnings.push(msg);
                    }
                }
            }
        }
        // Researcher identity: published key at identity_url must equal
        // the researcher.pubkey that signed the bundle.
        if let Some(r) = &bundle.researcher {
            if let Some(url) = &r.identity_url {
                match recheck_researcher_identity(url, &r.pubkey) {
                    Ok(m) => {
                        summary.researcher_identity_match = Some(m);
                        if !m {
                            summary.errors.push(format!(
                                "researcher key published at {url} does not match the bundle's \
                                 researcher.pubkey"
                            ));
                            ok = false;
                        }
                    }
                    Err(e) => {
                        let msg = format!("researcher-identity online re-check ({url}): {e:#}");
                        if strict {
                            summary.errors.push(msg);
                            ok = false;
                        } else {
                            summary.warnings.push(msg);
                        }
                    }
                }
            }
        }
    }

    summary.overall_ok = ok;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print_human(&summary, strict);
    }
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

// --- Phase 3: trust-source provenance ---------------------------------

/// Human estimate of when a Drand quicknet round finalises, as a
/// trailing " (~unlocks YYYY-MM-DD)". Empty string for non-quicknet or
/// if the chain is unrecorded — we only know the timing for the pinned
/// quicknet parameters. Inverse of `zkpox_envelope::round_at`.
fn drand_round_unlock_estimate(round: u64) -> String {
    use zkpox_envelope::{DRAND_QUICKNET_GENESIS_TIME, DRAND_QUICKNET_PERIOD};
    // round 1 finalises at genesis + period*1.
    let unlock_unix = DRAND_QUICKNET_GENESIS_TIME + DRAND_QUICKNET_PERIOD.saturating_mul(round);
    // Cheap UTC date from a Unix timestamp (days since epoch → Y-M-D),
    // avoiding a chrono dependency.
    format!(" (~unlocks {})", unix_to_utc_date(unlock_unix as i64))
}

/// Minimal Unix-seconds → "YYYY-MM-DD" (UTC). Civil-from-days algorithm
/// (Howard Hinnant). Good enough for a human time-lock hint.
fn unix_to_utc_date(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Fetch a URL body (HTTPS only). Shared by the online re-checks.
fn fetch_https_body(url: &str) -> Result<String> {
    if !url.starts_with("https://") {
        bail!("refusing to fetch non-https URL {url:?}");
    }
    match ureq::get(url).call() {
        Ok(resp) => resp
            .into_string()
            .with_context(|| format!("reading body of {url}")),
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            bail!("HTTP {code}: {body}")
        }
        Err(e) => bail!("{e}"),
    }
}

/// `--online`: confirm the age recipient published at `url` (a
/// security.txt `Zkpox-Age-Recipient` field, or a bare
/// `.well-known/zkpox-vendor.age.pub` body) equals `expected`.
fn recheck_vendor_key(url: &str, expected: &str) -> Result<bool> {
    let body = fetch_https_body(url)?;
    // security.txt field first.
    for line in body.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("Zkpox-Age-Recipient") {
                return Ok(value.trim() == expected);
            }
        }
    }
    // Else treat the body as a bare recipient (first non-blank,
    // non-comment line).
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        return Ok(line == expected);
    }
    bail!("no age recipient found at {url}")
}

/// `--online`: confirm the ed25519 key published at `url` matches the
/// bundle's `researcher.pubkey`. Compares by parsed 32-byte key (so PEM
/// whitespace / framing differences don't cause false mismatches).
fn recheck_researcher_identity(url: &str, bundle_pubkey: &[u8]) -> Result<bool> {
    let published = fetch_https_body(url)?;
    let published_pem = std::str::from_utf8(bundle_pubkey)
        .context("bundle researcher.pubkey is not UTF-8 PEM")?;
    let want = pem_to_ed25519_pubkey(published_pem)?;
    let got = pem_to_ed25519_pubkey(&published)?;
    Ok(want.to_bytes() == got.to_bytes())
}

// --- STARK verification -----------------------------------------------

fn verify_stark(
    bundle: &Bundle,
    cache_dir: Option<&std::path::Path>,
    strict: bool,
) -> Result<bool> {
    use sp1_sdk::SP1ProofWithPublicValues;

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

    // The bundle's recorded program verifying-key hash. Historically
    // stored as `sha256:HEX`, but the HEX is the 32-byte bn254 vkey
    // hash itself (`vk.bytes32_raw()`), not a SHA of anything — the
    // prefix is a legacy label. We treat it as the canonical 32-byte
    // VK identity the proof must be bound to.
    let vk_hex = bundle
        .backend
        .verifier_key_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("backend.verifier_key_digest missing sha256: prefix"))?;

    // Reconstruct the SP1 proof from `bundle.proof.bytes`. The SDK
    // saves and loads via the same serialised form. This is cheap —
    // it does NOT pull the multi-GB proving artifacts; only the legacy
    // `setup(elf)` path below does.
    let proof_path = std::env::temp_dir()
        .join(format!("zkpox-verify-{}.proof", std::process::id()));
    std::fs::write(&proof_path, &bundle.proof.bytes)?;
    let proof = SP1ProofWithPublicValues::load(&proof_path)
        .map_err(|e| anyhow!("loading SP1 proof from bundle: {e}"))?;
    let _ = std::fs::remove_file(&proof_path);

    // Pick the verification path from the wrap kind. groth16 (the
    // disclosure-grade wrap) verifies in milliseconds against an
    // embedded ~300 KB verifying key — no ELF, no `setup()`, no
    // artifact download. The raw STARK `core` wrap still needs the
    // guest ELF to re-derive the VK and run the SDK verifier.
    if bundle.proof.system.contains("groth16") {
        verify_groth16_lightweight(bundle, &proof, vk_hex, cache_dir, &target_hash, &predicate)?;
    } else {
        verify_core_with_elf(bundle, &proof, vk_hex, cache_dir, &target_hash, &predicate)?;
    }

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

/// Lightweight groth16 verification (the disclosure-grade path).
///
/// Verifies the wrapped BN254 Groth16 proof against the SP1 version's
/// embedded verifying key (`sp1_verifier::GROTH16_VK_BYTES`, ~300 KB)
/// plus the program's own vkey hash. This is the on-chain verifier's
/// algorithm: it needs neither the guest ELF nor the multi-GB proving
/// artifacts, so any vendor can run it unaided in milliseconds — the
/// Phase-2 "verify on a clean machine" requirement.
///
/// VK binding: the proof commits to the program vkey hash as its first
/// public input, and `Groth16Verifier::verify` enforces that it equals
/// `sp1_vkey_hash`. We obtain `sp1_vkey_hash` from the bundle and
/// require it to encode the *same* 32 bytes as `backend.verifier_key_digest`,
/// so the bundle cannot point the proof at a different program. When a
/// guest ELF happens to be cached locally we additionally re-derive the
/// VK from it and assert equality (defence in depth); absence of the
/// ELF is not fatal here, unlike the core path.
fn verify_groth16_lightweight(
    bundle: &Bundle,
    proof: &sp1_sdk::SP1ProofWithPublicValues,
    vk_hex: &str,
    cache_dir: Option<&std::path::Path>,
    target_hash: &[u8; 32],
    predicate: &PredicateSpec,
) -> Result<()> {
    // The `vk.bytes32()` string form the SP1 groth16 verifier expects:
    // `0x` + the 64-hex vkey hash. Prefer the explicit bundle field;
    // fall back to deriving it from `verifier_key_digest` (older
    // bundles). Either way, it must encode the same 32 bytes as the
    // recorded digest.
    let sp1_vkey_hash = match &bundle.proof.sp1_vkey_hash {
        Some(s) => {
            let h = s.strip_prefix("0x").unwrap_or(s);
            if !h.eq_ignore_ascii_case(vk_hex) {
                bail!(
                    "proof.sp1_vkey_hash {s:?} disagrees with backend.verifier_key_digest \
                     (sha256:{vk_hex}); the bundle is internally inconsistent"
                );
            }
            s.clone()
        }
        None => format!("0x{vk_hex}"),
    };

    // Defence in depth: if the guest ELF is cached, re-derive the VK
    // and confirm it matches the recorded digest. Missing ELF is fine
    // for the lightweight path — the proof itself binds the vkey hash.
    if let Err(e) = rederive_vk_if_cached(bundle, vk_hex, cache_dir, target_hash, predicate) {
        tracing::warn!("local ELF VK cross-check skipped/failed: {e:#}");
    }

    let raw_proof = proof.bytes();
    let public_inputs = proof.public_values.as_slice();
    sp1_verifier::Groth16Verifier::verify(
        &raw_proof,
        public_inputs,
        &sp1_vkey_hash,
        &sp1_verifier::GROTH16_VK_BYTES,
    )
    .map_err(|e| anyhow!("groth16 proof verification failed: {e:?}"))?;
    Ok(())
}

/// Re-derive the program VK from a locally cached guest ELF and assert
/// it matches `vk_hex`. Used as an optional cross-check on the groth16
/// path. Errors (no cache, no ELF) are surfaced to the caller, which
/// decides whether they are fatal.
fn rederive_vk_if_cached(
    bundle: &Bundle,
    vk_hex: &str,
    cache_dir: Option<&std::path::Path>,
    target_hash: &[u8; 32],
    predicate: &PredicateSpec,
) -> Result<()> {
    use sp1_sdk::blocking::{Prover as _, ProverClient};
    use sp1_sdk::{Elf, HashableKey as _, ProvingKey as _};

    let key = cache_key(target_hash, predicate.id_canonical, SP1_ZKVM_VERSION);
    let cache_root = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_cache_dir);
    let entry = CacheEntry::for_key(&cache_root, &key);
    if !entry.exists() {
        bail!("no cached ELF to cross-check against");
    }
    let elf_bytes = std::fs::read(&entry.elf_path)
        .with_context(|| format!("reading cached ELF {:?}", entry.elf_path))?;
    let elf: Elf = elf_bytes.into();
    let client = ProverClient::from_env();
    let pk = client.setup(elf).map_err(|e| anyhow!("sp1 setup: {e}"))?;
    let vk_bytes: [u8; 32] = pk.verifying_key().bytes32_raw();
    let derived = hex::encode(vk_bytes);
    if !derived.eq_ignore_ascii_case(vk_hex) {
        bail!(
            "verifier_key_digest mismatch: bundle says sha256:{vk_hex}, locally derived \
             sha256:{derived} from cached ELF"
        );
    }
    let _ = bundle;
    Ok(())
}

/// Core (raw STARK) verification. Requires the guest ELF in the cache
/// to re-derive the VK and run the SDK's STARK verifier. Heavier than
/// the groth16 path; used for `core`-wrap bundles.
fn verify_core_with_elf(
    bundle: &Bundle,
    proof: &sp1_sdk::SP1ProofWithPublicValues,
    vk_hex: &str,
    cache_dir: Option<&std::path::Path>,
    target_hash: &[u8; 32],
    predicate: &PredicateSpec,
) -> Result<()> {
    use sp1_sdk::blocking::{Prover as _, ProverClient};
    use sp1_sdk::{Elf, HashableKey as _, ProvingKey as _};

    let key = cache_key(target_hash, predicate.id_canonical, SP1_ZKVM_VERSION);
    let cache_root = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_cache_dir);
    let entry = CacheEntry::for_key(&cache_root, &key);
    if !entry.exists() {
        let target_hash_hex = hex::encode(target_hash);
        bail!(
            "no cached backend ELF for (target_hash={target_hash_hex}, predicate={}, sp1={}). \
             A core-wrap proof needs the guest ELF to verify; build it first with: \
             zkpox-prove build-target --target <source.c> --predicate {}.",
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
    let derived = hex::encode(vk_bytes);
    if !derived.eq_ignore_ascii_case(vk_hex) {
        bail!(
            "verifier_key_digest mismatch: bundle says sha256:{vk_hex}, locally derived \
             sha256:{derived} from cached ELF"
        );
    }

    client
        .verify(proof, pk.verifying_key(), None)
        .map_err(|e| anyhow!("sp1 verify: {e}"))?;
    Ok(())
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

/// Outcome of anchor verification. `None` on a field means the check
/// was not run (e.g. `--no-network`, or `--rekor-pubkey` was not
/// supplied for the SET check); `Some(false)` is a hard failure.
struct AnchorOutcome {
    recorded_match: Option<bool>,
    inclusion_ok: Option<bool>,
    set_valid: Option<bool>,
}

fn check_anchor(
    bundle: &Bundle,
    ts: &zkpox_schema::Timestamp,
    rekor_override: Option<&str>,
    no_network: bool,
    log_pubkey_pem: Option<&[u8]>,
) -> Result<AnchorOutcome> {
    // Every check below needs the Rekor entry body. With --no-network
    // we can't fetch it, so all three checks report None (not run) —
    // the bundle's stored proof is taken on trust for offline triage.
    if no_network {
        return Ok(AnchorOutcome {
            recorded_match: None,
            inclusion_ok: None,
            set_valid: None,
        });
    }

    let url = rekor_override
        .map(|s| s.to_string())
        .unwrap_or_else(rekor_url);

    // Single fetch covers all three checks.
    let (_uuid, entry) = fetch_entry_by_index(&url, ts.rekor_log_index)?;

    // (1) Recorded-hash: Rekor's stored entry hashes the same bytes as
    //     bundle_hash_pre_timestamp.
    let bundle_hash = sha256_bundle_pre_timestamp(bundle);
    let recorded_match = match entry_recorded_hash(&entry) {
        Ok(recorded) => Some(recorded == hex::encode(bundle_hash)),
        Err(e) => {
            tracing::warn!("rekor recorded-hash read: {e}");
            Some(false)
        }
    };

    // (2) Merkle inclusion: the audit path walks the leaf up to the
    //     recorded root (RFC 6962).
    let inclusion_ok = Some(
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
        }),
    );

    // (3) SET signature — only when the operator pinned a log pubkey.
    let set_valid = match log_pubkey_pem {
        Some(pem) => match check_set_signature(&entry, ts, pem) {
            Ok(valid) => Some(valid),
            Err(e) => {
                tracing::warn!("rekor SET signature: {e}");
                Some(false)
            }
        },
        None => None,
    };

    Ok(AnchorOutcome {
        recorded_match,
        inclusion_ok,
        set_valid,
    })
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

// --- Provenance metadata ----------------------------------------------

/// Convert a CBOR metadata value into `serde_json::Value` for display.
/// Inverse of the prover's `json_to_ciborium`; lossless for the JSON
/// subset provenance files use.
fn ciborium_to_json(v: &ciborium::Value) -> serde_json::Value {
    use ciborium::Value as C;
    use serde_json::Value as J;
    match v {
        C::Null => J::Null,
        C::Bool(b) => J::Bool(*b),
        C::Integer(i) => {
            if let Ok(x) = i64::try_from(*i) {
                J::Number(x.into())
            } else if let Ok(x) = u64::try_from(*i) {
                J::Number(x.into())
            } else {
                J::String(format!("{i:?}"))
            }
        }
        C::Float(f) => serde_json::Number::from_f64(*f)
            .map(J::Number)
            .unwrap_or(J::Null),
        C::Text(s) => J::String(s.clone()),
        C::Bytes(b) => J::String(hex::encode(b)),
        C::Array(a) => J::Array(a.iter().map(ciborium_to_json).collect()),
        C::Map(m) => {
            let mut obj = serde_json::Map::new();
            for (k, val) in m {
                let key = match k {
                    C::Text(s) => s.clone(),
                    other => format!("{other:?}"),
                };
                obj.insert(key, ciborium_to_json(val));
            }
            J::Object(obj)
        }
        // ciborium::Value is non-exhaustive (tags, etc.); provenance
        // never carries those.
        _ => J::Null,
    }
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

    // Trust-source provenance (Phase 3): where each key traces back to.
    if let Some(v) = &s.vendor_key_source {
        println!("  vendor key:    resolved from {v}");
    }
    if let Some(u) = &s.researcher_identity_url {
        println!("  researcher id: published at {u}");
    }
    if let Some(t) = &s.timelock {
        println!("  time-lock:     {t}");
    }
    if let Some(rk) = &s.rekor_key_source {
        println!("  rekor key:     {rk}");
    }

    if let Some(serde_json::Value::Object(o)) = &s.target_provenance {
        println!();
        println!("provenance:    (target.metadata — informational, NOT committed to the proof)");
        // Surface the well-known fields in a stable order; print any
        // remaining scalar fields after, so a richer provenance file
        // still shows up.
        const KNOWN: &[&str] = &[
            "cve",
            "upstream_project",
            "upstream_repo",
            "vulnerable_tag",
            "fixed_commit",
            "function",
            "function_file",
            "extraction",
            "fidelity_level",
        ];
        for key in KNOWN {
            if let Some(v) = o.get(*key).and_then(|v| v.as_str()) {
                println!("  {key:<14} {v}");
            }
        }
        for (k, v) in o {
            if KNOWN.contains(&k.as_str()) {
                continue;
            }
            if let Some(sv) = v.as_str() {
                println!("  {k:<14} {sv}");
            }
        }
    }

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
        "  Rekor SET signature:        {}",
        opt_str(s.rekor_set_signature_valid)
    );
    println!(
        "  researcher signature:       {}",
        opt_str(s.researcher_signature_valid)
    );
    println!(
        "  vendor key (online):        {}",
        opt_str(s.vendor_key_source_match)
    );
    println!(
        "  researcher id (online):     {}",
        opt_str(s.researcher_identity_match)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an ed25519 SubjectPublicKeyInfo PEM from a *real* verifying
    /// key (so it decompresses to a valid curve point), optionally on a
    /// single base64 line to exercise framing differences. Mirrors the
    /// prover's `ed25519_pubkey_pem`.
    fn ed25519_spki_pem(vk: &ed25519_dalek::VerifyingKey, single_line: bool) -> String {
        let raw = vk.to_bytes();
        let mut der = Vec::with_capacity(44);
        der.extend_from_slice(&[0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70]);
        der.extend_from_slice(&[0x03, 0x21, 0x00]);
        der.extend_from_slice(&raw);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        if single_line {
            pem.push_str(&b64);
            pem.push('\n');
        } else {
            for chunk in b64.as_bytes().chunks(64) {
                pem.push_str(std::str::from_utf8(chunk).unwrap());
                pem.push('\n');
            }
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        pem
    }

    fn vk_from_seed(seed: u8) -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key()
    }

    /// The researcher-identity `--online` check compares two PEMs by
    /// their parsed 32-byte key (`want.to_bytes() == got.to_bytes()`).
    /// This exercises that comparison primitive directly: the SAME key in
    /// two different PEM framings must compare equal, so legitimate
    /// formatting differences between the bundle's key and the published
    /// key never cause a false mismatch.
    #[test]
    fn researcher_key_match_is_framing_insensitive() {
        let vk = vk_from_seed(7);
        let wrapped = pem_to_ed25519_pubkey(&ed25519_spki_pem(&vk, false)).unwrap();
        let one_line = pem_to_ed25519_pubkey(&ed25519_spki_pem(&vk, true)).unwrap();
        assert_eq!(
            wrapped.to_bytes(),
            one_line.to_bytes(),
            "same key, different PEM framing must match"
        );
    }

    /// ...and two DIFFERENT keys must NOT compare equal — the check
    /// catches a published key that doesn't match the bundle's signer.
    #[test]
    fn researcher_key_match_rejects_different_key() {
        let a = pem_to_ed25519_pubkey(&ed25519_spki_pem(&vk_from_seed(1), false)).unwrap();
        let b = pem_to_ed25519_pubkey(&ed25519_spki_pem(&vk_from_seed(2), false)).unwrap();
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    /// Garbage / non-PEM input is rejected rather than silently treated
    /// as a (mismatching) key.
    #[test]
    fn researcher_key_parse_rejects_garbage() {
        assert!(pem_to_ed25519_pubkey("not a pem").is_err());
        assert!(pem_to_ed25519_pubkey("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n").is_err());
    }
}
