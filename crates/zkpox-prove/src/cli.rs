//! CLI definition. Kept separate from the orchestration so the
//! command surface is reviewable on its own.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "zkpox-prove",
    about = "Generate zero-knowledge proofs of exploit — the prover half of zkpox.",
    version,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Build (or refresh) the SP1 guest ELF + VK for a given
    /// (target, predicate) pair. Caches the result.
    BuildTarget(BuildTargetArgs),

    /// End-to-end: prove → optionally seal envelope → optionally
    /// anchor → write bundle.cbor.
    Prove(ProveArgs),
}

/// Wrap mode passed to SP1. `core` is the raw STARK (multi-MB, fast
/// to produce); `groth16` is the on-chain-friendly wrap (~1.7 KB,
/// slow to produce, requires the ~6 GB circuit-artifact download
/// once). Bundles intended for real disclosure should use `groth16`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Wrap {
    Core,
    Groth16,
}

impl Wrap {
    pub fn system_label(self) -> &'static str {
        match self {
            Wrap::Core => "sp1-stark-core/v6.0.1",
            Wrap::Groth16 => "sp1-groth16-bn254/v6.0.1",
        }
    }
}

#[derive(clap::Args, Debug)]
pub struct BuildTargetArgs {
    /// Path to the freestanding C source exposing `zkpox_victim`.
    #[arg(long)]
    pub target: PathBuf,

    /// Predicate ID. One of:
    ///   crash-only, memory-safety::oob-write
    #[arg(long, default_value = "memory-safety::oob-write")]
    pub predicate: String,

    /// Logical buffer size handed to the victim. Tied to the bug
    /// shape; default 32 fits CVE-2017-9047 and is safe for 16-byte
    /// stack-BOF / off-by-one bugs.
    #[arg(long, default_value_t = 32)]
    pub buf_size: usize,

    /// Path to the zkpox-guest source tree. Defaults to
    /// `ZKPOX_GUEST_SOURCE` env var, then to auto-detection
    /// (walks up from the prover binary's location).
    #[arg(long)]
    pub guest_source: Option<PathBuf>,

    /// Override the cache directory. Defaults to
    /// `ZKPOX_CACHE_DIR` env var, then `$XDG_CACHE_HOME/zkpox`, then
    /// `~/.cache/zkpox`.
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,

    /// Rebuild even if a cache entry exists.
    #[arg(long)]
    pub force: bool,

    /// Print the resulting (cache_key, target_hash, vk_digest) as
    /// JSON to stdout.
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args, Debug)]
pub struct ProveArgs {
    #[arg(long)]
    pub target: PathBuf,

    #[arg(long, default_value = "memory-safety::oob-write")]
    pub predicate: String,

    #[arg(long, default_value_t = 32)]
    pub buf_size: usize,

    #[arg(long)]
    pub witness: PathBuf,

    #[arg(long, value_enum, default_value_t = Wrap::Groth16)]
    pub wrap: Wrap,

    /// Where to write the CBOR bundle.
    #[arg(long)]
    pub output: PathBuf,

    /// age recipient (`age1...` X25519 pubkey) for the vendor
    /// envelope. Omit to skip envelope sealing.
    #[arg(long)]
    pub vendor_pubkey: Option<String>,

    /// Time-lock duration (e.g. `90d`, `30m`, `8s`). Defaults to
    /// Project Zero's 90-day CVD norm.
    #[arg(long, default_value = "90d")]
    pub tlock_duration: String,

    /// Skip Sigstore Rekor anchoring.
    #[arg(long)]
    pub no_anchor: bool,

    /// Override the Rekor URL. Defaults to `ZKPOX_REKOR_URL` env var
    /// or `https://rekor.sigstore.dev`.
    #[arg(long)]
    pub rekor_url: Option<String>,

    /// Path to an ed25519 secret key (raw 32 bytes) used to sign
    /// the bundle. Generates an ephemeral key if omitted.
    #[arg(long)]
    pub researcher_key: Option<PathBuf>,

    /// Skip researcher signature entirely.
    #[arg(long)]
    pub anonymous: bool,

    /// Optional URL where the target binary/source can be fetched
    /// later. Recorded in `bundle.target.url`.
    #[arg(long)]
    pub target_url: Option<String>,

    /// Optional path to a provenance JSON file (e.g. a target's
    /// `*.provenance.json`). Its object is embedded verbatim under
    /// `bundle.target.metadata.provenance`, binding the bundle to the
    /// upstream source the target was extracted from (repo, tag, fixed
    /// commit, function, extraction notes). Surfaced by the verifier so
    /// a reviewer can trace harness → upstream.
    #[arg(long)]
    pub provenance: Option<PathBuf>,

    /// Where the target source can be retrieved.
    #[arg(long)]
    pub source_url: Option<String>,

    /// Guest source override (see `build-target --guest-source`).
    #[arg(long)]
    pub guest_source: Option<PathBuf>,

    /// Cache override (see `build-target --cache-dir`).
    #[arg(long)]
    pub cache_dir: Option<PathBuf>,
}
