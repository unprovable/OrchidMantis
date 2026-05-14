//! # zkpox SP1 guest
//!
//! Single, generic guest program. The build script compiles one C
//! target into a static archive exposing `zkpox_victim`; this guest
//! dispatches the chosen predicate (selected at build time by a Cargo
//! feature) against that victim and the prover's witness.
//!
//! ## Witness format (Layer-1)
//!
//! ```text
//! witness_bytes        — raw exploit input fed to the victim's `input` pointer.
//! ```
//!
//! No framing prefix. The target's identity is bound by the guest
//! ELF's verifying key (because the C source is linked in at build
//! time); the witness is purely the exploit input.
//!
//! ## Public-values commit order
//!
//! See `zkpox_schema::public_values` for the canonical layout. This
//! guest writes:
//!
//! 1. `PUBLIC_VALUES_VERSION` (u32)
//! 2. `TARGET_HASH` (32 bytes, build-time const)
//! 3. predicate.ID_CANONICAL (u32)
//! 4. predicate.VERSION (u32)
//! 5. backend_id (u32 = 1, static-c)
//! 6. backend_version (u32 = 1)
//! 7. flags (u32, packed (inv_flag, vuln_flag) bits)
//! 8. outputs_len (u32)
//! 9. outputs bytes (variable)

// `#![no_main]` is only required when the SP1 zkVM build picks up
// this crate. Host-side `cargo build` / `cargo test` produces a real
// binary with a normal entrypoint — see `host_main` below.
#![cfg_attr(target_os = "zkvm", no_main)]

#[cfg(target_os = "zkvm")]
sp1_zkvm::entrypoint!(zkvm_entry);

#[cfg(target_os = "zkvm")]
fn zkvm_entry() {
    zkvm_main::main();
}

#[cfg(not(target_os = "zkvm"))]
fn main() {
    // Host-build no-op. The real entry is the SP1-zkvm one above.
    eprintln!(
        "zkpox-guest: this binary is the SP1 guest program. \
         Build with `cargo prove build` and run inside the SP1 zkVM. \
         This host-side stub does nothing."
    );
}

#[cfg(target_os = "zkvm")]
mod zkvm_main {
    use zkpox_predicates::{outputs::ToWire, Predicate, TargetRunner};

    // `TARGET_HASH` is emitted by build.rs at OUT_DIR/target_hash.rs.
    include!(concat!(env!("OUT_DIR"), "/target_hash.rs"));

    /// Hard-pinned to match the backend metadata crate
    /// (`zkpox-backend-static-c::BACKEND_VERSION`). Drift between
    /// these is a wire-breaking change — the verifier reads
    /// `backend_version` from the public values and refuses
    /// versions outside the table it ships with.
    const BACKEND_ID: u32 = 0x0000_0001; // static-c, see registry.rs
    const BACKEND_VERSION: u32 = 1;

    /// Schema version word committed first. Must match
    /// `zkpox_schema::public_values::PUBLIC_VALUES_VERSION`.
    const PUBLIC_VALUES_VERSION: u32 = 2;

    extern "C" {
        /// The single victim function the C target exposes. Linked
        /// in by build.rs. Signature is fixed by zkpox-predicates'
        /// `TargetRunner` trait.
        fn zkpox_victim(
            buf: *mut core::ffi::c_char,
            buf_size: usize,
            input: *const core::ffi::c_char,
            n: usize,
        ) -> core::ffi::c_char;
    }

    /// `TargetRunner` impl that delegates to the linked-in C
    /// `zkpox_victim` symbol. `BUF_SIZE` is set by the
    /// `ZKPOX_BUF_SIZE` env var at build time, defaulting to 32.
    struct StaticCTarget;
    impl TargetRunner for StaticCTarget {
        fn invoke(
            &self,
            buf: *mut core::ffi::c_char,
            buf_size: usize,
            input: *const core::ffi::c_char,
            n: usize,
        ) {
            unsafe {
                let _ = zkpox_victim(buf, buf_size, input, n);
            }
        }
        fn buf_size(&self) -> usize {
            BUF_SIZE
        }
    }

    /// `BUF_SIZE` is a build-time const supplied by the host via the
    /// `ZKPOX_BUF_SIZE` env var read in build.rs. Default 32 covers
    /// CVE-2017-9047 (which needs >= 32 for the bypass) and the
    /// 16-byte simpler targets (oversizing the buffer is harmless).
    pub(crate) const BUF_SIZE: usize = match option_env!("ZKPOX_BUF_SIZE") {
        Some(s) => parse_usize_const(s.as_bytes()),
        None => 32,
    };
    const fn parse_usize_const(bytes: &[u8]) -> usize {
        let mut acc = 0usize;
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b < b'0' || b > b'9' {
                panic!("ZKPOX_BUF_SIZE must be base-10 digits");
            }
            acc = acc * 10 + (b - b'0') as usize;
            i += 1;
        }
        acc
    }

    fn commit_public_values<Out: ToWire>(
        predicate_id: u32,
        predicate_version: u32,
        inv_flag: bool,
        vuln_flag: bool,
        outputs: &Out,
    ) {
        // Order MUST match zkpox_schema::public_values comments.
        sp1_zkvm::io::commit(&PUBLIC_VALUES_VERSION);
        // SP1's commit takes a serializable value; the 32-byte target
        // hash commits cleanly as a [u8; 32].
        sp1_zkvm::io::commit(&TARGET_HASH);
        sp1_zkvm::io::commit(&predicate_id);
        sp1_zkvm::io::commit(&predicate_version);
        sp1_zkvm::io::commit(&BACKEND_ID);
        sp1_zkvm::io::commit(&BACKEND_VERSION);
        let flags = (inv_flag as u32) | ((vuln_flag as u32) << 1);
        sp1_zkvm::io::commit(&flags);
        let wire = outputs.to_wire();
        sp1_zkvm::io::commit(&(wire.len() as u32));
        // Commit each byte individually keeps the on-wire layout
        // independent of how SP1 frames a Vec<u8>.
        for &b in &wire {
            sp1_zkvm::io::commit(&b);
        }
    }

    pub(crate) fn main() {
        // SP1's zkvm environment provides std (with the alloc-via-bump
        // allocator embedded in sp1-zkvm), so `Vec` resolves through
        // the prelude — no explicit `extern crate alloc` needed.
        let witness: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
        let runner = StaticCTarget;

        // Compile-time predicate selection. Exactly one feature flag
        // must be active; the cfg_if-like #[cfg] chain catches the
        // misconfigured case at build time.
        #[cfg(feature = "predicate-crash-only")]
        {
            type P = zkpox_predicates::redzone::CrashOnly;
            let (outputs, inv_flag, vuln_flag) = P::run(&runner, &witness);
            commit_public_values::<<P as Predicate>::Outputs>(
                P::ID_CANONICAL,
                P::VERSION,
                inv_flag,
                vuln_flag,
                &outputs,
            );
        }
        #[cfg(feature = "predicate-oob-write")]
        {
            type P = zkpox_predicates::redzone::MemorySafetyOobWrite;
            let (outputs, inv_flag, vuln_flag) = P::run(&runner, &witness);
            commit_public_values::<<P as Predicate>::Outputs>(
                P::ID_CANONICAL,
                P::VERSION,
                inv_flag,
                vuln_flag,
                &outputs,
            );
        }
        #[cfg(not(any(feature = "predicate-crash-only", feature = "predicate-oob-write")))]
        compile_error!(
            "zkpox-guest must be built with exactly one predicate feature; e.g. \
             `cargo prove build --features predicate-oob-write`. Available: \
             `predicate-crash-only`, `predicate-oob-write`."
        );
    }
}

