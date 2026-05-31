//! Redzone scanning primitive and the two predicates built on top.
//!
//! The redzone is a region of memory placed on either side of the
//! caller's logical buffer, filled with a known **expected pattern**
//! before the target function runs. After the target returns, the
//! redzone is scanned: any byte whose post-call value disagrees with
//! the expected pattern is treated as evidence that the target wrote
//! outside its buffer.
//!
//! ## Two pattern flavours
//!
//! - `pattern_uniform`: every redzone byte is `0xA5`. Cheapest,
//!   simplest, but trivially defeated by an exploit that happens to
//!   write `0xA5` past the end. `crash-only` uses this.
//!
//! - `pattern_varying`: the expected byte at position `p` is
//!   `0xA5 XOR ((p * 0x9E37_79B1) >> 24)`. Every redzone position
//!   has a distinct expected byte. An attacker who didn't
//!   pre-compute the table matches a single position with
//!   probability `1/256`; matching `N` consecutive overflow bytes
//!   drops to `(1/256)^N`. `memory-safety::oob-write` uses this.
//!
//! ## False positives / negatives
//!
//! - **Adversarial witness generators**: a producer who computes
//!   `pattern_varying` and crafts a witness to match it defeats the
//!   probabilistic check. The Layer-1 backend documents this; the
//!   `memory-safety::shadow-allocation` predicate (stubbed) will
//!   replace the probabilistic redzone with deterministic
//!   per-allocation shadow tables.
//!
//! - **False positives** are impossible in the current target set:
//!   none of the targets legitimately writes the position-varying
//!   pattern outside their buffer. A future heap-aware target that
//!   did would need a different predicate.
//!
//! ## Buffer geometry
//!
//! ```text
//! ┌───────────────────┬──────────────────┬───────────────────┐
//! │  leading redzone  │   buffer (n)     │ trailing redzone  │
//! │       LEADING     │    buf_size      │   ≥ MIN_TRAILING  │
//! └───────────────────┴──────────────────┴───────────────────┘
//! ```
//!
//! The trailing redzone is sized to absorb any input length so a
//! deep overrun doesn't escape into memory the SP1 executor doesn't
//! track — see `scan_around`.

extern crate alloc;
use alloc::vec::Vec;

use core::ffi::c_uchar;

use crate::outputs::{CrashOnlyOutputs, OobWriteOutputs};
use crate::{BufferKind, Predicate, TargetRunner};

/// Default leading-redzone width.
pub const LEADING: usize = 16;
/// Minimum trailing-redzone width. Grown automatically per witness
/// length so deep overruns stay inside the scanned window.
pub const MIN_TRAILING: usize = 16;

/// Uniform canary value used by `crash-only`.
pub const UNIFORM_CANARY: c_uchar = 0xA5;

#[inline]
pub fn pattern_uniform(_pos: usize) -> c_uchar {
    UNIFORM_CANARY
}

#[inline]
pub fn pattern_varying(pos: usize) -> c_uchar {
    let mix = (pos as u32).wrapping_mul(0x9E37_79B1u32);
    UNIFORM_CANARY ^ ((mix >> 24) as u8)
}

/// One observed redzone-scan result.
#[derive(Debug, Default, Clone, Copy)]
pub struct Scan {
    pub dirty: bool,
    pub count: u32,
    /// `i32::MIN` if nothing changed. Negative ⇔ underflow.
    pub first_offset: i32,
}

/// Run `runner.invoke` with a buffer surrounded by `pattern` in both
/// the leading and trailing redzones; scan the redzone afterwards.
///
/// `runner.buf_size()` is the logical buffer width visible to the
/// target. The trailing redzone is at least `min_trailing` bytes and
/// always large enough to contain any plausible overrun for an input
/// of length `witness.len()`.
pub fn scan_around<T, F>(
    runner: &T,
    witness: &[u8],
    leading_redzone: usize,
    min_trailing_redzone: usize,
    pattern: F,
) -> Scan
where
    T: TargetRunner,
    F: Fn(usize) -> c_uchar,
{
    let buf_size = runner.buf_size();
    let trailing = min_trailing_redzone.max(witness.len().saturating_sub(buf_size) + 8);
    let total = leading_redzone + buf_size + trailing;

    let mut window: Vec<c_uchar> = (0..total).map(&pattern).collect();

    // SAFETY: `window` lives for the duration of this call; the
    // caller's pointer into `window[leading_redzone..]` is valid
    // for `buf_size` bytes; the input pointer is valid for
    // `witness.len()` bytes. The target is forbidden by trait
    // contract from accessing memory beyond those bounds.
    let buf_ptr = unsafe {
        window.as_mut_ptr().add(leading_redzone) as *mut core::ffi::c_char
    };
    runner.invoke(
        buf_ptr,
        buf_size,
        witness.as_ptr() as *const core::ffi::c_char,
        witness.len(),
    );

    let mut scan = Scan {
        first_offset: i32::MIN,
        ..Scan::default()
    };
    for (i, &b) in window.iter().enumerate() {
        if i >= leading_redzone && i < leading_redzone + buf_size {
            // Inside the legitimate buffer — writes are expected.
            continue;
        }
        if b != pattern(i) {
            scan.dirty = true;
            scan.count = scan.count.saturating_add(1);
            if scan.first_offset == i32::MIN {
                let signed = i as i64 - leading_redzone as i64;
                scan.first_offset = signed as i32;
            }
        }
    }
    scan
}

// --- Predicate: crash-only ---------------------------------------------

/// The cheapest, simplest predicate. Uniform-`0xA5` canary; flags as
/// vulnerable if any redzone byte changed.
pub struct CrashOnly;

impl Predicate for CrashOnly {
    const ID: &'static str = "crash-only";
    const ID_CANONICAL: u32 = 0x0000_0001;
    const VERSION: u32 = 1;
    type Outputs = CrashOnlyOutputs;

    fn run<T: TargetRunner>(target: &T, witness: &[u8]) -> (Self::Outputs, bool, bool) {
        let _ = BufferKind::Stack; // future predicates will branch on this
        let scan = scan_around(target, witness, LEADING, MIN_TRAILING, pattern_uniform);
        let inv_flag = false; // execution itself is always valid in Layer-1
        let vuln_flag = scan.dirty;
        (
            CrashOnlyOutputs { crashed: vuln_flag },
            inv_flag,
            vuln_flag,
        )
    }
}

// --- Predicate: memory-safety::oob-write -------------------------------

/// Position-varying redzone. Catches single-byte overruns that
/// happened to write `0xA5` (which the uniform variant misses), and
/// reports the byte count + first offset of the violation.
pub struct MemorySafetyOobWrite;

impl Predicate for MemorySafetyOobWrite {
    const ID: &'static str = "memory-safety::oob-write";
    const ID_CANONICAL: u32 = 0x0000_0002;
    const VERSION: u32 = 1;
    type Outputs = OobWriteOutputs;

    fn run<T: TargetRunner>(target: &T, witness: &[u8]) -> (Self::Outputs, bool, bool) {
        let scan = scan_around(target, witness, LEADING, MIN_TRAILING, pattern_varying);
        let inv_flag = false;
        let vuln_flag = scan.dirty;
        (
            OobWriteOutputs {
                count: scan.count,
                first_offset: scan.first_offset,
            },
            inv_flag,
            vuln_flag,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A trivial in-memory runner with a classic unbounded-copy bug
    // (no bound check, copies n bytes into buf).
    struct BugRunner {
        buf_size: usize,
    }
    impl TargetRunner for BugRunner {
        fn invoke(
            &self,
            buf: *mut core::ffi::c_char,
            _buf_size: usize,
            input: *const core::ffi::c_char,
            n: usize,
        ) {
            // SAFETY: test-only; the redzone scanner provides the
            // backing memory and we keep n inside it.
            unsafe {
                for i in 0..n {
                    *buf.add(i) = *input.add(i);
                }
            }
        }
        fn buf_size(&self) -> usize {
            self.buf_size
        }
    }

    #[test]
    fn crash_only_detects_overflow_with_non_a5_byte() {
        let runner = BugRunner { buf_size: 16 };
        // 17-byte witness whose 17th byte is NOT 0xA5 → must be detected.
        let witness: Vec<u8> = (0..17).map(|i| i as u8).collect();
        let (out, inv, vuln) = CrashOnly::run(&runner, &witness);
        assert_eq!(inv, false);
        assert_eq!(vuln, true);
        assert_eq!(out.crashed, true);
    }

    #[test]
    fn crash_only_blind_to_overflow_with_a5_byte() {
        let runner = BugRunner { buf_size: 16 };
        let mut witness = vec![0u8; 17];
        witness[16] = 0xA5; // overflow byte happens to match the canary
        let (_out, _inv, vuln) = CrashOnly::run(&runner, &witness);
        // This is the documented blind spot: uniform-canary misses
        // an exact-match overflow. The OOB predicate must NOT miss it.
        assert_eq!(vuln, false, "uniform canary is blind to 0xA5 overflows");
    }

    #[test]
    fn oob_write_catches_overflow_with_a5_byte() {
        let runner = BugRunner { buf_size: 16 };
        let mut witness = vec![0u8; 17];
        witness[16] = 0xA5;
        let (out, inv, vuln) = MemorySafetyOobWrite::run(&runner, &witness);
        assert_eq!(inv, false);
        assert_eq!(vuln, true, "varying pattern must catch 0xA5 overflows");
        assert_eq!(out.count, 1);
        assert_eq!(out.first_offset, 16, "overflow lands at offset = buf_size");
    }

    #[test]
    fn benign_witness_produces_no_violation() {
        let runner = BugRunner { buf_size: 16 };
        let witness = vec![0u8; 16]; // fits exactly
        let (_, _, vuln) = MemorySafetyOobWrite::run(&runner, &witness);
        assert_eq!(vuln, false);
    }
}
