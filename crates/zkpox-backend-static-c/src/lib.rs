//! # zkpox-backend-static-c
//!
//! Layer-1 backend metadata + build pipeline glue. The static-C
//! backend takes a freestanding C source file exposing a victim
//! function with this exact signature:
//!
//! ```c
//! char zkpox_victim(char *buf, size_t buf_size, const char *input, size_t n);
//! ```
//!
//! At `zkpox-prove build-target` time, the source is cross-compiled
//! to RISC-V64 and linked into the SP1 guest. The guest's
//! verifying-key digest is then a function of (target source bytes,
//! predicate ID, sp1_zkvm version) — that triple is what every
//! standalone tool consuming this crate uses to derive the cache key
//! for the resulting ELF + VK.
//!
//! ## Why a thin crate
//!
//! The SP1 SDK is a heavy host-side dependency (downloads the Groth16
//! circuit artifacts on first use; ~6 GB compressed). Putting it
//! behind a separate `zkpox-prove` binary keeps this crate tiny: it
//! exposes only the spec types and cache-key derivation, both of
//! which are needed by the verifier (which must not depend on the
//! SDK's wrapping circuitry just to look up a VK from a bundle).
//!
//! ## Witness layout the guest expects
//!
//! For the static-C backend, the witness fed to the SP1 guest is the
//! raw exploit bytes — no framing prefix. The target ID is implicit
//! in the (target_hash, predicate_id) pair that uniquely identifies
//! the guest ELF.
//!
//! This is a deliberate departure from RAPTOR's MVP, which prepends
//! a `target_id` byte. There, the guest dispatched at runtime among
//! three baked-in targets; here, the guest is built fresh per
//! (target, predicate) pair, so no dispatch is needed.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub use zkpox_schema::registry::{BACKEND_STATIC_C, PREDICATE_CRASH_ONLY, PREDICATE_MEMORY_SAFETY_OOB_WRITE};

/// Pinned canonical ID and version. Bumped when the build pipeline,
/// the guest ELF skeleton, or the witness framing changes.
pub const BACKEND_VERSION: u32 = 1;
pub const BACKEND_KIND: &str = BACKEND_STATIC_C;

/// User-facing target spec.
#[derive(Debug, Clone)]
pub struct TargetSpec {
    pub source_path: PathBuf,
    /// The symbol the guest will call. Must match the function name
    /// in the C source. Defaults to `zkpox_victim`.
    pub entry_symbol: String,
    /// Logical buffer size handed to the victim. Tied to the bug
    /// shape — e.g. CVE-2017-9047 needs `buf_size = 32` for the
    /// bypass window to be reachable; the off-by-one and stack-BOF
    /// examples use 16.
    pub buf_size: usize,
}

impl TargetSpec {
    pub fn new<P: Into<PathBuf>>(source_path: P) -> Self {
        Self {
            source_path: source_path.into(),
            entry_symbol: "zkpox_victim".to_string(),
            buf_size: 16,
        }
    }

    pub fn with_entry(mut self, sym: impl Into<String>) -> Self {
        self.entry_symbol = sym.into();
        self
    }

    pub fn with_buf_size(mut self, n: usize) -> Self {
        self.buf_size = n;
        self
    }

    /// `sha256(source_bytes)`. Used as `PublicValues.target_hash` and
    /// as one component of the cache key.
    pub fn compute_hash(&self) -> std::io::Result<[u8; 32]> {
        let bytes = std::fs::read(&self.source_path)?;
        Ok(Sha256::digest(&bytes).into())
    }
}

/// Predicate spec mirror. The string form lives in the bundle; the
/// canonical u32 lives in the proof's public values.
#[derive(Debug, Clone)]
pub struct PredicateSpec {
    pub id: String,
    pub id_canonical: u32,
    pub version: u32,
}

impl PredicateSpec {
    pub fn from_id(id: &str) -> Self {
        Self {
            id: id.to_string(),
            id_canonical: zkpox_schema::registry::predicate_id(id),
            // Pinned table for known predicates. Unknown predicates
            // get version 0 — the verifier in --strict mode will
            // refuse those.
            version: match id {
                PREDICATE_CRASH_ONLY => 1,
                PREDICATE_MEMORY_SAFETY_OOB_WRITE => 1,
                _ => 0,
            },
        }
    }
}

/// Cache key for the built guest ELF + VK pair. Stable across
/// rebuilds when (target source bytes, predicate id, sp1_zkvm
/// version) are unchanged. The `sp1_zkvm` version is included so a
/// toolchain bump produces a fresh cache entry rather than silently
/// re-using an ELF built against the old SP1.
pub fn cache_key(
    target_hash: &[u8; 32],
    predicate_id_canonical: u32,
    sp1_zkvm_version: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(b"zkpox-backend-static-c\0");
    h.update(&BACKEND_VERSION.to_le_bytes());
    h.update(target_hash);
    h.update(&predicate_id_canonical.to_le_bytes());
    h.update(sp1_zkvm_version.as_bytes());
    format!("static-c-{}", hex::encode(h.finalize()))
}

/// Default on-disk cache root: `$XDG_CACHE_HOME/zkpox` or
/// `~/.cache/zkpox`. Override via `ZKPOX_CACHE_DIR` env var.
pub fn default_cache_dir() -> PathBuf {
    if let Ok(p) = std::env::var("ZKPOX_CACHE_DIR") {
        return PathBuf::from(p);
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return PathBuf::from(xdg).join("zkpox");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".cache").join("zkpox");
    }
    PathBuf::from("./.zkpox-cache")
}

/// File layout inside the cache dir for one (target, predicate) pair.
pub struct CacheEntry {
    pub root: PathBuf,
    pub elf_path: PathBuf,
    pub vk_path: PathBuf,
    pub meta_path: PathBuf,
}

impl CacheEntry {
    pub fn for_key(cache_dir: &Path, key: &str) -> Self {
        let root = cache_dir.join(key);
        Self {
            elf_path: root.join("guest.elf"),
            vk_path: root.join("vk.bin"),
            meta_path: root.join("meta.json"),
            root,
        }
    }

    pub fn exists(&self) -> bool {
        self.elf_path.is_file() && self.vk_path.is_file() && self.meta_path.is_file()
    }
}

/// Predicate-to-cargo-feature mapping. The zkpox-guest crate declares
/// one feature per predicate; selecting a feature picks the predicate
/// the guest links against. Unknown predicates have no feature — the
/// caller must reject them before reaching the build pipeline.
pub fn predicate_feature(id: &str) -> Option<&'static str> {
    match id {
        PREDICATE_CRASH_ONLY => Some("predicate-crash-only"),
        PREDICATE_MEMORY_SAFETY_OOB_WRITE => Some("predicate-oob-write"),
        _ => None,
    }
}

/// Hash a freshly-extracted SP1 verifying key bytes blob to the
/// canonical 32-byte digest the bundle records. The exact byte
/// representation of `vk` depends on the SP1 SDK; we hash whatever
/// the SDK gives us so producer and verifier match.
pub fn vk_bytes_to_digest(vk_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(vk_bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn cache_key_is_deterministic() {
        let h: [u8; 32] = [7; 32];
        let k1 = cache_key(&h, 2, "6.0.1");
        let k2 = cache_key(&h, 2, "6.0.1");
        assert_eq!(k1, k2);
    }

    #[test]
    fn cache_key_diverges_on_sp1_version() {
        let h: [u8; 32] = [7; 32];
        assert_ne!(cache_key(&h, 2, "6.0.1"), cache_key(&h, 2, "6.0.2"));
    }

    #[test]
    fn target_spec_hash_round_trip() -> std::io::Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;
        write!(tmp.as_file(), "char zkpox_victim() {{ return 0; }}\n")?;
        let spec = TargetSpec::new(tmp.path());
        let h = spec.compute_hash()?;
        assert_eq!(h.len(), 32);
        Ok(())
    }

    #[test]
    fn predicate_feature_mapping() {
        assert_eq!(
            predicate_feature(PREDICATE_CRASH_ONLY),
            Some("predicate-crash-only"),
        );
        assert_eq!(
            predicate_feature(PREDICATE_MEMORY_SAFETY_OOB_WRITE),
            Some("predicate-oob-write"),
        );
        assert_eq!(predicate_feature("experimental::made-up"), None);
    }
}
