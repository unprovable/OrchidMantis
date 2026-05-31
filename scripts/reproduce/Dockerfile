# syntax=docker/dockerfile:1
#
# Reproducible guest-build environment for zkpox (Orchid Mantis).
#
# Goal (Phase 2): a vendor on a clean machine reproduces the guest
# verifying-key digest *byte for byte*. This image pins the whole
# toolchain so `zkpox-prove build-target` emits the same VK digest the
# disclosure bundle records — independent of the researcher's laptop.
#
# Build (from the repo root):
#   docker build -f scripts/reproduce/Dockerfile -t zkpox-reproduce .
#
# Reproduce the VK + verify the committed bundle:
#   docker run --rm zkpox-reproduce
#
# The default CMD runs scripts/reproduce/verify-vk.sh, which builds the
# target guest, asserts the VK digest equals the pinned EXPECTED_VK, and
# verifies the committed example bundle via the lightweight groth16 path.
#
# Pins (keep in lock-step with versions.txt and Cargo.lock):
#   - Rust:        1.85 (also enforced by rust-toolchain.toml)
#   - SP1:         sp1-sdk / sp1-zkvm / sp1-verifier 6.2.0 (Cargo.lock)
#   - cargo-prove: installed by sp1up, pinned via SP1UP_VERSION
#   - clang/lld:   Debian LLVM (multi-target; ships the RISC-V backend
#                  Apple's bundled clang lacks)

ARG RUST_VERSION=1.85
FROM rust:${RUST_VERSION}-bookworm

# cargo-prove / succinct toolchain release that resolves the 6.2.0 SP1
# crates and produces cargo-prove v6.1.0. Override at build time if a
# pin needs bumping: --build-arg SP1UP_VERSION=vX.Y.Z
ARG SP1UP_VERSION=v6.1.0

# Go toolchain for sp1-recursion-gnark-ffi: its build.rs shells out to
# `go build` to compile the gnark Groth16 verifier into a static
# library (libsp1gnark.a). Pinned for reproducibility; Debian's
# golang-go is too old for SP1's gnark.
ARG GO_VERSION=1.23.4

# --- System cross-compile toolchain for the freestanding C target -----
# Stock LLVM is multi-target, so `clang --target=riscv64-...` works
# without a separate RISC-V cross GCC. lld + llvm give us a linker and
# llvm-ar for the static archive build.rs produces.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        lld \
        llvm \
        curl \
        ca-certificates \
        git \
        protobuf-compiler \
        libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

# --- Go toolchain (for sp1-recursion-gnark-ffi's libsp1gnark.a) -------
# Installed from the official tarball (not apt) so the version is pinned
# and recent enough for SP1's gnark FFI. Put it on PATH for the build.
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
        -o /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:${PATH}"

# build.rs picks Homebrew clang on macOS; on Linux it falls back to
# PATH `clang`. Make the archiver explicit too (build.rs probes a list,
# but pinning avoids surprises).
ENV ZKPOX_CLANG=clang
ENV ZKPOX_AR=llvm-ar

# --- SP1 toolchain (cargo-prove + succinct rustc channel) -------------
# sp1up installs into ~/.sp1/bin and registers the `succinct` rustup
# toolchain that `cargo prove build` cross-compiles the guest with.
RUN curl -L https://sp1up.succinct.xyz | bash \
    && /root/.sp1/bin/sp1up --version ${SP1UP_VERSION}
ENV PATH="/root/.sp1/bin:${PATH}"

WORKDIR /src
COPY . /src

# Build the host binaries. Cargo.lock is committed, so this resolves the
# exact 6.2.0 SP1 crate set — do NOT pass --locked off.
RUN cargo build --release --locked -p zkpox-prove -p zkpox-verify

# Sanity: the toolchain is present and the right version.
RUN cargo prove --version && rustc --version && go version && clang --version | head -1

ENTRYPOINT []
CMD ["bash", "scripts/reproduce/verify-vk.sh"]
