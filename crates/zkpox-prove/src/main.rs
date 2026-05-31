//! `zkpox-prove` — the standalone prover binary.
//!
//! Two subcommands:
//!
//! - `build-target` — cross-compile the SP1 guest with the user's
//!   target C source linked in and the chosen predicate's feature
//!   selected. Caches the resulting ELF + verifying-key digest under
//!   `~/.cache/zkpox/static-c-<key>/`. Subsequent prove invocations
//!   for the same (target, predicate) hit the cache.
//!
//! - `prove` — the end-to-end disclosure pipeline:
//!     1. Resolve (target, predicate) → cached backend.
//!     2. Run SP1 with the witness as private input.
//!     3. Verify the proof in-process; refuse to bundle on failure.
//!     4. Decode public values; consistency-check against schema.
//!     5. Optionally seal the witness in a layered envelope
//!        (AES + age + Drand tlock).
//!     6. Optionally anchor the bundle hash to Sigstore Rekor.
//!     7. Optionally attach a researcher signature.
//!     8. Emit `bundle.cbor`.
//!
//! Real binding hashes from day one — no placeholder
//! "placeholder-vk-1.5" / "harness-1.5" sha256s. The
//! `proof.verifier_key_digest` is `sp1-sdk`'s actual VK digest and
//! `target.hash` is the sha256 of the target source bytes.

mod build;
mod cli;
mod orchestrate;
mod vendor;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,sp1_sdk=warn")),
        )
        .init();

    let args = cli::Cli::parse();
    match args.command {
        cli::Command::BuildTarget(args) => orchestrate::cmd_build_target(args),
        cli::Command::Prove(args) => orchestrate::cmd_prove(args),
    }
}
