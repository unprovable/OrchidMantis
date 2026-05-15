# targets/

Example freestanding C targets the standalone tool's `static-c`
backend can ship proofs against. Lifted from RAPTOR's `core/zkpox/`
MVP, with one rename: each target exposes its bug in a function
called `zkpox_victim` rather than `zkpox_target_NN_victim`, because
each target compiles into a freshly built SP1 guest ELF — there is
no longer a runtime dispatch over multiple targets.

| File | Bug class | CVE | Buffer size |
|---|---|---|---|
| [`01-stack-bof.c`](01-stack-bof.c) | classic stack BOF (no bound check) | — | 16 |
| [`02-off-by-one.c`](02-off-by-one.c) | textbook off-by-one (`i <= buf_size`) | — | 16 |
| [`03-libxml2-cve-2017-9047.c`](03-libxml2-cve-2017-9047.c) | libxml2 `xmlSnprintfElementContent` stale-len | [CVE-2017-9047](https://nvd.nist.gov/vuln/detail/CVE-2017-9047) | 32 |
| [`04-openssl-cve-2016-6303.c`](04-openssl-cve-2016-6303.c) | OpenSSL `MDC2_Update` integer-overflow bound check | [CVE-2016-6303](https://nvd.nist.gov/vuln/detail/CVE-2016-6303) | 8 |

## Writing your own target

The `static-c` backend's contract is:

```c
#include <stddef.h>

char zkpox_victim(
    char *buf, size_t buf_size,
    const char *input, size_t n);
```

The function must:

- Be **freestanding**. No libc; the SP1 guest's RISC-V environment
  has no syscalls and no standard library. If you need `strlen` /
  `memcpy` semantics, write them open-coded (see
  `03-libxml2-cve-2017-9047.c` for an example).
- Treat `(buf, buf_size)` as the caller-supplied output buffer. The
  redzone scanner places known-pattern bytes around `buf`; any bytes
  outside `[buf, buf+buf_size)` that the function modifies are
  treated as evidence of a memory-safety violation.
- Treat `(input, n)` as the **witness** bytes the prover supplied —
  this is the exploit input. Do not assume any particular structure
  beyond what your bug requires.

The returned `char` is irrelevant to the proof; it's there only so
the compiler keeps the writes live (and so a native build of the
same source can sanity-check the bug outside the zkVM).

## Compile flags

The guest's `build.rs` (at `crates/zkpox-guest/build.rs`) invokes
clang with:

```
--target=riscv64-unknown-none-elf
-march=rv64im -mabi=lp64 -mcmodel=medany
-ffreestanding -fno-stack-protector -fno-pic -O0
```

`-fno-stack-protector` is deliberate — we want the bug to actually
corrupt memory so the predicate's redzone trips. `__stack_chk_fail`
does not exist in the freestanding SP1 environment regardless.

## Scope reminder

The `memory-safety::oob-write` predicate detects bytes outside the
buffer that don't match the position-varying pattern fill. It does
**not** prove control-flow hijack, RCE, exploit reliability, or
attacker control over the overwriting bytes. See `docs/SCOPE.md`.
