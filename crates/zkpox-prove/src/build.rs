//! Build pipeline: drive `cargo prove build` to produce the
//! per-target SP1 guest ELF, then derive the verifying-key digest.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use zkpox_backend_static_c::{
    cache_key, default_cache_dir, predicate_feature, CacheEntry, PredicateSpec, TargetSpec,
    BACKEND_VERSION,
};

/// The pinned sp1-zkvm version we build against. Drives the cache
/// key; bumping SP1 invalidates every cached ELF.
pub const SP1_ZKVM_VERSION: &str = "6.0.1";

/// Result of one `build-target` invocation.
#[derive(Debug, Clone, Serialize)]
pub struct BuiltBackend {
    pub cache_key: String,
    pub cache_dir: PathBuf,
    pub elf_path: PathBuf,
    pub vk_path: PathBuf,
    pub meta_path: PathBuf,
    pub target_hash_hex: String,
    pub predicate_id: String,
    pub predicate_id_canonical: u32,
    pub predicate_version: u32,
    pub vk_digest_hex: String,
    pub sp1_zkvm_version: String,
    pub buf_size: usize,
}

/// Cache metadata persisted alongside the ELF. Verifiers don't read
/// this — it's a producer-side breadcrumb so `zkpox-prove prove`
/// can hand the bundle the correct metadata without re-deriving it.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CacheMeta {
    pub target_hash_hex: String,
    pub predicate_id: String,
    pub predicate_id_canonical: u32,
    pub predicate_version: u32,
    pub vk_digest_hex: String,
    pub sp1_zkvm_version: String,
    pub buf_size: usize,
}

/// Locate the zkpox-guest source tree. Resolution order:
///   1. `--guest-source` CLI arg (highest precedence)
///   2. `ZKPOX_GUEST_SOURCE` env var
///   3. Walk up from `current_exe()` looking for
///      `crates/zkpox-guest/Cargo.toml`.
pub fn resolve_guest_source(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        let cargo = p.join("Cargo.toml");
        if !cargo.is_file() {
            bail!("--guest-source {p:?} does not contain a Cargo.toml");
        }
        return Ok(p.to_path_buf());
    }
    if let Ok(env_p) = std::env::var("ZKPOX_GUEST_SOURCE") {
        let p = PathBuf::from(env_p);
        let cargo = p.join("Cargo.toml");
        if !cargo.is_file() {
            bail!("ZKPOX_GUEST_SOURCE={p:?} does not contain a Cargo.toml");
        }
        return Ok(p);
    }
    let exe = std::env::current_exe().context("locating zkpox-prove binary")?;
    let mut dir = exe.parent().unwrap_or(Path::new(".")).to_path_buf();
    loop {
        let candidate = dir.join("crates").join("zkpox-guest").join("Cargo.toml");
        if candidate.is_file() {
            return Ok(dir.join("crates").join("zkpox-guest"));
        }
        if !dir.pop() {
            bail!(
                "could not locate zkpox-guest source. Pass --guest-source <path/to/crates/zkpox-guest> \
                 or set ZKPOX_GUEST_SOURCE."
            );
        }
    }
}

/// Build the guest ELF for `(target, predicate)`, caching the
/// result. Returns the `BuiltBackend` describing where the artifacts
/// live and what they bind.
pub fn build_or_load(
    target: &TargetSpec,
    predicate: &PredicateSpec,
    guest_source: &Path,
    cache_dir: Option<&Path>,
    force: bool,
) -> Result<BuiltBackend> {
    let target_hash = target.compute_hash()?;
    let key = cache_key(&target_hash, predicate.id_canonical, SP1_ZKVM_VERSION);
    let cache_root = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_cache_dir);
    let entry = CacheEntry::for_key(&cache_root, &key);

    if entry.exists() && !force {
        let meta_bytes = std::fs::read(&entry.meta_path)?;
        let meta: CacheMeta = serde_json::from_slice(&meta_bytes)
            .context("parsing cached meta.json")?;
        // Defensive: cached meta should round-trip the target hash; if it
        // doesn't, the cache is corrupt and we rebuild.
        if meta.target_hash_hex == hex::encode(target_hash)
            && meta.predicate_id == predicate.id
            && meta.sp1_zkvm_version == SP1_ZKVM_VERSION
        {
            return Ok(BuiltBackend {
                cache_key: key,
                cache_dir: entry.root.clone(),
                elf_path: entry.elf_path.clone(),
                vk_path: entry.vk_path.clone(),
                meta_path: entry.meta_path.clone(),
                target_hash_hex: meta.target_hash_hex,
                predicate_id: meta.predicate_id,
                predicate_id_canonical: meta.predicate_id_canonical,
                predicate_version: meta.predicate_version,
                vk_digest_hex: meta.vk_digest_hex,
                sp1_zkvm_version: meta.sp1_zkvm_version,
                buf_size: meta.buf_size,
            });
        }
        tracing::warn!(?key, "cache entry exists but meta drifted; rebuilding");
    }

    std::fs::create_dir_all(&entry.root).context("creating cache dir")?;
    let feature = predicate_feature(&predicate.id)
        .ok_or_else(|| anyhow!("unknown predicate {:?}; not registered in zkpox-backend-static-c", predicate.id))?;

    // Drive `cargo prove build` against the guest crate. Environment:
    //   - ZKPOX_TARGET_C  — absolute path to target source (build.rs reads it)
    //   - ZKPOX_BUF_SIZE  — informational; the guest pins this at compile time
    //   - SP1_BUILD_PROGRAM — none (we use plain cargo invocation)
    let abs_target = target
        .source_path
        .canonicalize()
        .with_context(|| format!("canonicalize target source {:?}", target.source_path))?;

    // `cargo prove build` is SP1's custom subcommand; unlike vanilla
    // `cargo build` it doesn't accept `--manifest-path` (see the SP1
    // CLI source). We invoke it from inside the guest crate's
    // directory instead. The output ELF lands either at
    // <guest>/elf/<binary-name> or at the cargo target directory
    // (location varies across SP1 releases — see the candidate list
    // below).
    tracing::info!(
        guest_source = ?guest_source,
        target = ?abs_target,
        predicate = %predicate.id,
        feature = %feature,
        "invoking cargo prove build"
    );
    let status = Command::new("cargo")
        .arg("prove")
        .arg("build")
        .arg("--features")
        .arg(feature)
        .current_dir(guest_source)
        .env("ZKPOX_TARGET_C", &abs_target)
        .env("ZKPOX_BUF_SIZE", target.buf_size.to_string())
        .status()
        .context("invoking `cargo prove build` — is the SP1 toolchain installed? See https://docs.succinct.xyz/getting-started/install.")?;
    if !status.success() {
        bail!("cargo prove build failed with status {status:?}");
    }

    // SP1's build emits the ELF at one of three locations depending
    // on the SP1 release and whether the guest crate has its own
    // cargo target dir or shares the workspace's:
    //
    //   <guest>/elf/<bin-name>
    //   <guest>/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/<bin-name>
    //   <workspace-root>/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/<bin-name>
    //
    // The third path is what SP1 6.0+ uses when the guest is a
    // workspace member — `cargo prove build` honours the workspace's
    // shared target directory rather than carving out its own. Search
    // all three.
    let workspace_root = guest_source
        .parent()                       // <workspace>/crates
        .and_then(|p| p.parent())      // <workspace>
        .map(|p| p.to_path_buf());
    let mut candidates = vec![
        guest_source.join("elf").join("zkpox-guest"),
        guest_source
            .join("target")
            .join("elf-compilation")
            .join("riscv64im-succinct-zkvm-elf")
            .join("release")
            .join("zkpox-guest"),
    ];
    if let Some(root) = workspace_root {
        candidates.push(
            root.join("target")
                .join("elf-compilation")
                .join("riscv64im-succinct-zkvm-elf")
                .join("release")
                .join("zkpox-guest"),
        );
    }
    let elf_src = candidates
        .iter()
        .find(|p| p.is_file())
        .ok_or_else(|| {
            anyhow!(
                "could not find built guest ELF in any of: {:?}. \
                 cargo prove build may have changed its output path; check `cargo prove --version`.",
                candidates,
            )
        })?;
    let elf_bytes = std::fs::read(elf_src).context("reading built guest ELF")?;
    std::fs::write(&entry.elf_path, &elf_bytes).context("writing cached ELF")?;

    // Derive the SP1 verifying key. `sp1-sdk::ProverClient::from_env()`
    // + `setup(elf)` returns the SP1ProvingKey, whose
    // `verifying_key().hash_bytes()` gives the stable VK digest. (We
    // use whichever API the pinned SP1 SDK exposes; see
    // `vk_digest_for_elf` below for the version-specific call.)
    let vk_digest = vk_digest_for_elf(&elf_bytes).context("deriving SP1 verifying-key digest")?;
    std::fs::write(&entry.vk_path, vk_digest)?;

    let meta = CacheMeta {
        target_hash_hex: hex::encode(target_hash),
        predicate_id: predicate.id.clone(),
        predicate_id_canonical: predicate.id_canonical,
        predicate_version: predicate.version,
        vk_digest_hex: hex::encode(vk_digest),
        sp1_zkvm_version: SP1_ZKVM_VERSION.to_string(),
        buf_size: target.buf_size,
    };
    std::fs::write(&entry.meta_path, serde_json::to_vec_pretty(&meta)?)?;

    let _ = BACKEND_VERSION; // referenced for compile-time pinning of the cache structure

    Ok(BuiltBackend {
        cache_key: key,
        cache_dir: entry.root,
        elf_path: entry.elf_path,
        vk_path: entry.vk_path,
        meta_path: entry.meta_path,
        target_hash_hex: meta.target_hash_hex,
        predicate_id: meta.predicate_id,
        predicate_id_canonical: meta.predicate_id_canonical,
        predicate_version: meta.predicate_version,
        vk_digest_hex: meta.vk_digest_hex,
        sp1_zkvm_version: meta.sp1_zkvm_version,
        buf_size: meta.buf_size,
    })
}

/// Derive the canonical 32-byte VK digest from the SP1 verifying
/// key.
///
/// `bytes32_raw` is the on-chain-friendly form (used by SP1's TEE
/// integrations); for the Groth16 wrap it is the canonical reference
/// digest. We hash the SDK's returned bytes if they're a non-32-byte
/// length so producer and verifier stay consistent regardless of
/// SDK-version drift in the digest API.
fn vk_digest_for_elf(elf_bytes: &[u8]) -> Result<[u8; 32]> {
    use sp1_sdk::blocking::{Prover as _, ProverClient};
    use sp1_sdk::{Elf, HashableKey as _, ProvingKey as _};
    let client = ProverClient::from_env();
    let elf: Elf = elf_bytes.to_vec().into();
    let pk = client.setup(elf).map_err(|e| anyhow!("sp1 setup: {e}"))?;
    // `bytes32_raw` is the on-chain-friendly form for Groth16 (vs
    // `bytes32` which returns the same digest as a 0x-prefixed
    // string). Both encode the same 32-byte VK fingerprint.
    let vk_bytes: [u8; 32] = pk.verifying_key().bytes32_raw();
    Ok(vk_bytes)
}
