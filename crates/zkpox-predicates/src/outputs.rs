//! Tiny hand-rolled binary wire format for predicate outputs.
//!
//! Avoids pulling serde/ciborium into the guest. The format is
//! intentionally trivial: every output type implements `ToWire`,
//! which produces a length-prefixed byte vector that the SP1 guest
//! commits as part of the public values. The host crate
//! (`zkpox-prove`) re-decodes into CBOR for the bundle.
//!
//! Layout per output type is documented at the type's definition; if
//! you change an output layout, bump that predicate's `VERSION`.

extern crate alloc;
use alloc::vec::Vec;

/// Implemented by every `Predicate::Outputs`. The wire bytes must be
/// stable across rebuilds for a given predicate version — they get
/// committed onto the proof.
pub trait ToWire {
    fn to_wire(&self) -> Vec<u8>;
}

/// Append-only writer for the wire bytes. Fixed-width little-endian
/// encoding everywhere; choosing LE matches SP1's RISC-V endianness.
pub struct Buf {
    inner: Vec<u8>,
}

impl Buf {
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }
    pub fn push_bool(&mut self, b: bool) {
        self.inner.push(b as u8);
    }
    pub fn push_u32(&mut self, v: u32) {
        self.inner.extend_from_slice(&v.to_le_bytes());
    }
    pub fn push_i32(&mut self, v: i32) {
        self.inner.extend_from_slice(&v.to_le_bytes());
    }
    pub fn push_u64(&mut self, v: u64) {
        self.inner.extend_from_slice(&v.to_le_bytes());
    }
    pub fn into_inner(self) -> Vec<u8> {
        self.inner
    }
}

impl Default for Buf {
    fn default() -> Self {
        Self::new()
    }
}

// --- Crash-only predicate output ---------------------------------------

/// `crash-only` produces a single bool: did any byte of the redzone
/// change? Cheap; low false-negative resistance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashOnlyOutputs {
    pub crashed: bool,
}

impl ToWire for CrashOnlyOutputs {
    fn to_wire(&self) -> Vec<u8> {
        let mut b = Buf::new();
        b.push_bool(self.crashed);
        b.into_inner()
    }
}

/// Decode wire bytes produced by `CrashOnlyOutputs::to_wire`.
///
/// Used by the host to re-render outputs into the CBOR bundle. The
/// guest never decodes; encoding is one-way at proof time.
pub fn decode_crash_only(wire: &[u8]) -> Option<CrashOnlyOutputs> {
    if wire.len() < 1 {
        return None;
    }
    Some(CrashOnlyOutputs {
        crashed: wire[0] != 0,
    })
}

// --- memory-safety::oob-write predicate output -------------------------

/// `memory-safety::oob-write` produces a richer description of the
/// observed violation:
///
/// - `count` — total bytes of the redzone whose post-call value did
///   not match the position-varying expected pattern. Bigger means
///   "wider overrun" or "deeper underrun."
/// - `first_offset` — signed offset (in bytes, from `buf[0]`) of the
///   first changed redzone byte. Negative ⇒ underflow, positive ⇒
///   overflow past the end of `buf`. `i32::MIN` is the sentinel
///   meaning "no change observed" (use the `count == 0` guard
///   instead; the sentinel is for the wire-format completeness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OobWriteOutputs {
    pub count: u32,
    pub first_offset: i32,
}

impl ToWire for OobWriteOutputs {
    fn to_wire(&self) -> Vec<u8> {
        let mut b = Buf::new();
        b.push_u32(self.count);
        b.push_i32(self.first_offset);
        b.into_inner()
    }
}

pub fn decode_oob_write(wire: &[u8]) -> Option<OobWriteOutputs> {
    if wire.len() < 8 {
        return None;
    }
    let count = u32::from_le_bytes(wire[0..4].try_into().ok()?);
    let first_offset = i32::from_le_bytes(wire[4..8].try_into().ok()?);
    Some(OobWriteOutputs {
        count,
        first_offset,
    })
}
