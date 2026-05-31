# DISCLOSURE-WORKFLOW — using zkpox for real coordinated disclosure

This document is a recipe, not a contract. Adapt it to your local
legal and policy constraints; zkpox itself does not perform legal
evaluation, and producing a proof requires running the exploit
(which is "access" under CFAA-equivalent laws in most jurisdictions).

## When zkpox is the right tool

- You hold a working exploit for a memory-safety bug in a freestanding C
  function (or any code path you can wrap in `zkpox_victim`).
- You want to **prove** the bug exists, **publicly**, without revealing
  the exploit.
- You want the vendor to receive the witness immediately.
- You want a published disclosure timeline that fires automatically,
  even if the vendor sits on the bug.
- You want a tamper-evident timestamp anchoring the artifact to a
  moment in time.

## When zkpox is NOT yet the right tool

- The bug requires concurrency / weak memory models (TOCTOU, data races).
- The vulnerability is a side channel (timing, cache, speculation).
- The exploit's effect is "code execution" or "control-flow hijack" — the
  v0.1 predicates detect memory-safety violations only, not their
  downstream consequences.
- The bug is in a smart contract / EVM target — those need predicates
  not yet shipped.

See `docs/SCOPE.md` for the precise statement of what current bundles
do and do not prove. See `docs/ROADMAP.md` for what's coming.

## End-to-end recipe

### 0. Pre-flight

```sh
# Install the SP1 toolchain (https://docs.succinct.xyz/getting-started/install).
curl -L https://sp1up.succinct.xyz | bash && sp1up

# Build zkpox.
cd /path/to/zkpox
cargo build --release
```

### 1. Extract the bug into a freestanding C function

The target's contract is one `zkpox_victim(buf, buf_size, input, n)`
function.

```c
#include <stddef.h>

char zkpox_victim(
    char *buf, size_t buf_size,
    const char *input, size_t n)
{
    /* the bug, faithfully reproduced */
    /* the witness is the bytes in `input` */
}
```

**Fidelity matters more than convenience here.** A bundle binds to
`sha256(target.c)`, so a reviewer's confidence is exactly their
confidence that `target.c` faithfully represents the real code. Two
patterns:

- **Reduction** (`targets/03-libxml2-cve-2017-9047.c`): a hand-retyped
  paraphrase of the bug. Quick to write, but a reviewer must trust the
  retype.
- **Verbatim extraction** (`targets/04-libxml2-cve-2017-9047-upstream.c`,
  *recommended*): the **real** upstream function + real type defs,
  copied character-for-character, with only freestanding libc shims
  added (the guest links no libc). The proof then binds to the code as
  upstream wrote it. Pair it with a `*.provenance.json` (see step 3)
  recording the upstream repo, vulnerable tag, fixed commit, and
  function, and verify the bug still fires natively before proving:

  ```sh
  ./tests/run-realsource-repro.sh   # no SP1 toolchain needed
  ```

  Note the **caller geometry**: the real function only reaches the bug
  when its buffer is near-full, so verbatim targets carry the real
  caller's `--buf-size` (5000 for this CVE) rather than a shrunk one.

### 2. Build the backend

```sh
./target/release/zkpox-prove build-target \
    --target targets/my-bug.c \
    --predicate memory-safety::oob-write \
    --buf-size 64
```

For the verbatim libxml2 example, the buffer size must match the real
caller geometry:

```sh
./target/release/zkpox-prove build-target \
    --target targets/04-libxml2-cve-2017-9047-upstream.c \
    --predicate memory-safety::oob-write \
    --buf-size 5000
```

Outputs the cache key, cached ELF path, and the
`verifier_key_digest`. Subsequent invocations against the same
target + predicate hit the cache.

### 3. Prove + bundle

```sh
./target/release/zkpox-prove prove \
    --target targets/my-bug.c \
    --predicate memory-safety::oob-write \
    --buf-size 64 \
    --witness path/to/exploit-input.bin \
    --wrap groth16 \
    --vendor-pubkey "$(cat vendor.age.pub)" \
    --tlock-duration 90d \
    --output bundle.cbor
```

- `--wrap groth16` is required for shippable bundles (~1.7 KB
  on-chain-friendly proof). `--wrap core` is faster but produces a
  multi-MB raw STARK suitable only for local testing.
- `--vendor-pubkey` is the vendor's published age recipient
  (`age1...`). Omit to skip envelope sealing; the bundle then proves
  the bug exists but doesn't carry the witness.
- `--tlock-duration` is the public-decryption deadline. Defaults to
  `90d` (Project Zero norm). Accepts `Nd`, `Nh`, `Nm`, `Ns`.
- The bundle is anchored to Sigstore Rekor by default. Skip with
  `--no-anchor` for testing; the public bundle then has no
  cryptographic time priority.
- `--provenance <file.json>` embeds an upstream-provenance object under
  `target.metadata.provenance` (repo, vulnerable tag, fixed commit,
  function, extraction notes), so a verifier can trace the harness back
  to upstream. Use the target's `*.provenance.json`:
  `--provenance targets/04-libxml2-cve-2017-9047-upstream.provenance.json`.

### 4. Send the bundle

The bundle is a single `.cbor` file. Share it:

- Publicly, alongside your normal CVD advisory (so anyone can verify
  the bug is real).
- Privately, to the vendor's CVD inbox (alongside their normal
  vulnerability report). The vendor can decrypt the witness
  immediately via the age path.

Where to publish:

- A GitHub release on the project's repository.
- A pinned tweet or fediverse post that links the file.
- The vendor's bug-bounty submission system if they accept arbitrary
  attachments.
- A community-curated zkpox bundle index, if one comes to exist
  (community project; not part of v0.1).

### 5. Wait the disclosure window

The Rekor timestamp is your proof of priority. The time-lock fires
automatically at T+90d (or whatever you chose) regardless of vendor
action. After that, anyone can fetch the matching Drand round
signature and decrypt the witness via the public path.

### 6. Verify your own bundle (sanity check)

```sh
./target/release/zkpox-verify bundle.cbor --strict \
    --target targets/my-bug.c
```

Strict mode fails on any deferred or unverifiable check. `--target
<local path>` triggers the re-hash check so you confirm the bundle
binds to the source you intended.

Two trust-root flags matter at acceptance time (Phases 3–4):

- `--online` re-fetches the bundle's recorded trust sources and confirms
  they still match: the vendor key at `vendor_key_source_url` and the
  researcher key at `researcher.identity_url`. The Rekor SET is checked
  against the pinned public Sigstore key by default (`--rekor-pubkey`
  overrides).
- `--cvd` is the disclosure-grade gate: it **refuses** a bundle marked
  `experimental` (pre-1.0 bundles are experimental by default). Use it
  when this verification is the acceptance decision for a real
  disclosure; omit it for triage, where the experimental banner is just a
  warning.

## Researcher attribution

zkpox supports three attribution modes:

- **Signed (default)**. An ephemeral ed25519 key is generated and signs
  `bundle_hash_pre_researcher(bundle)`. The pubkey ships inside the
  bundle. Verifiers can confirm the signature is well-formed but have
  no out-of-band way to bind it to a real-world identity unless the
  key is published elsewhere (your security.txt, your social-media
  profile, etc.). Pass `--researcher-key path/to/sk.bin` to use a
  persistent ed25519 secret key (raw 32 bytes).
- **Anonymous**. Pass `--anonymous` to omit the researcher field
  entirely. Priority is then established only by the Rekor timestamp.
- **Pseudonymous via social media**. The same as signed, but you tweet
  the pubkey (or post it to a GitHub profile / fediverse / Mastodon
  account) so the verifier has an out-of-band binding.

The Rekor anchor itself is signed by a *separate* ephemeral key (the
"anchoring identity") — that key is discarded after anchoring; what
matters for the public record is that Rekor recorded the bundle hash,
not who signed the Rekor entry.

## Legal posture (not legal advice)

Producing a zkpox proof requires running the exploit. In most
jurisdictions this is "access" under the relevant computer-misuse
law. A disclosure-engineer workflow is a useful
draft-writing tool for citing safe harbors: vendor CVD policy, EU CRA
Article 13, the recent Belgian CVD framework, the US DMCA §1201
security-research exemption, the EU Cybercrime Directive amendments
ENISA recommended. zkpox does not encode any of these — your
disclosure operator is responsible for ensuring legal cover.

## Threat-model summary

See `docs/THREAT-MODEL.md`. Two points particularly worth flagging
when running a disclosure:

1. **Pin your SP1 version.** Subscribe to Succinct's security
   advisories. If a soundness bug lands in your pinned release,
   re-issue affected bundles under a patched release.
2. **Use a curated vendor-key source.** v0.1 punts on the vendor-key
   registry. Pulling `--vendor-pubkey` from a vendor's security.txt
   over HTTPS with certificate validation is the minimum bar;
   ideally use a community-curated mapping signed by the vendor's
   existing CVD contacts.
