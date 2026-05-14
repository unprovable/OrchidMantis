//! Guest build.rs — cross-compile the user-supplied C target into a
//! static archive the SP1 guest can link against.
//!
//! Driven by two environment variables:
//!
//! - `ZKPOX_TARGET_C` — path to the target C source file. Required.
//! - `ZKPOX_CLANG`    — override path to a clang binary with the
//!                       RISC-V backend. Defaults to Homebrew LLVM on
//!                       macOS, otherwise `clang` on PATH.
//!
//! And two compile-time outputs:
//!
//! - The C source is compiled to `libzkpox_target.a` and put on the
//!   linker's search path; the guest's `extern "C"` binding resolves
//!   against it.
//! - The SHA-256 of the C source bytes is written into a
//!   `target_hash.rs` file the guest includes — that const becomes
//!   `PublicValues.target_hash`.
//!
//! ## Why we don't go through `cc-rs`
//!
//! `cc-rs` derives flags from `CARGO_TARGET` and friends. SP1's
//! target (`riscv64im-succinct-zkvm-elf`) is not a real LLVM platform,
//! and Apple's bundled clang lacks the RISC-V backend. Manual clang
//! invocation with explicit `--target=riscv64-unknown-none-elf
//! -march=rv64im -mabi=lp64` is shorter than fighting `cc-rs`'s
//! heuristics. This mirrors RAPTOR's MVP build script (RAPTOR
//! identified the same problem during Phase 0).

use std::path::PathBuf;
use std::process::Command;

fn pick_clang() -> String {
    if let Ok(p) = std::env::var("ZKPOX_CLANG") {
        return p;
    }
    if cfg!(target_os = "macos") {
        let brew = "/opt/homebrew/opt/llvm/bin/clang";
        if PathBuf::from(brew).exists() {
            return brew.to_string();
        }
    }
    "clang".to_string()
}

fn compile_c(clang: &str, src: &PathBuf, obj: &PathBuf) {
    let status = Command::new(clang)
        .args([
            "--target=riscv64-unknown-none-elf",
            "-march=rv64im",
            "-mabi=lp64",
            "-mcmodel=medany",
            "-ffreestanding",
            "-fno-stack-protector",
            "-fno-pic",
            "-O0",
            "-Wall",
            "-Wextra",
            "-c",
        ])
        .arg(src)
        .args(["-o"])
        .arg(obj)
        .status()
        .expect("failed to invoke clang for the target C source");
    if !status.success() {
        panic!("clang failed compiling {}", src.display());
    }
}

fn archive_objects(archive: &PathBuf, objs: &[PathBuf]) {
    let archiver_candidates = [
        std::env::var("ZKPOX_AR").unwrap_or_default(),
        "/opt/homebrew/opt/llvm/bin/llvm-ar".to_string(),
        "llvm-ar".to_string(),
        "ar".to_string(),
    ];
    let mut last_err = None;
    for ar in archiver_candidates.iter().filter(|s| !s.is_empty()) {
        let mut cmd = Command::new(ar);
        cmd.arg("rcs").arg(archive);
        for obj in objs {
            cmd.arg(obj);
        }
        match cmd.status() {
            Ok(s) if s.success() => {
                last_err = None;
                break;
            }
            Ok(s) => last_err = Some(format!("{ar} returned {s}")),
            Err(e) => last_err = Some(format!("{ar} not runnable: {e}")),
        }
    }
    if let Some(msg) = last_err {
        panic!("no archiver succeeded: {msg}");
    }
}

fn write_target_hash_rs(out_dir: &PathBuf, src_bytes: &[u8]) {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(src_bytes).into();
    let mut rs = String::from("pub const TARGET_HASH: [u8; 32] = [");
    for (i, b) in digest.iter().enumerate() {
        if i > 0 {
            rs.push(',');
        }
        rs.push_str(&format!("0x{b:02x}"));
    }
    rs.push_str("];\n");
    std::fs::write(out_dir.join("target_hash.rs"), rs)
        .expect("writing target_hash.rs");
}

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));

    // Hosting `cargo build` on a non-SP1 target should still succeed
    // — the workspace's `default-members` excludes the guest, but if a
    // user runs `cargo build -p zkpox-guest` outside SP1's environment
    // they should see a clean diagnostic. We detect "we're not
    // cross-compiling to SP1's triple" and short-circuit to writing a
    // zero target_hash.rs so the rest of the crate still compiles.
    let target = std::env::var("TARGET").unwrap_or_default();
    let is_sp1 = target.starts_with("riscv64") && target.contains("succinct");

    let target_c = std::env::var("ZKPOX_TARGET_C").ok();

    let target_bytes = match &target_c {
        Some(path) => {
            let bytes = std::fs::read(path)
                .unwrap_or_else(|e| panic!("reading ZKPOX_TARGET_C={path}: {e}"));
            println!("cargo:rerun-if-changed={path}");
            bytes
        }
        None => {
            // No target set: host build of the workspace. Write a
            // placeholder hash so the include! in main.rs resolves;
            // do NOT attempt the RISC-V cross-compile.
            Vec::new()
        }
    };

    write_target_hash_rs(&out_dir, &target_bytes);
    println!("cargo:rerun-if-env-changed=ZKPOX_TARGET_C");
    println!("cargo:rerun-if-env-changed=ZKPOX_CLANG");
    println!("cargo:rerun-if-env-changed=ZKPOX_AR");

    if !is_sp1 || target_c.is_none() {
        // Host build: stop here. main.rs is still cross-compiled when
        // SP1 invokes us; this path exists so plain `cargo check` in
        // the workspace doesn't fail.
        return;
    }

    let clang = pick_clang();
    let src = PathBuf::from(target_c.unwrap());
    let obj = out_dir.join("zkpox_target.o");
    compile_c(&clang, &src, &obj);

    let archive = out_dir.join("libzkpox_target.a");
    archive_objects(&archive, &[obj]);

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=zkpox_target");
}
