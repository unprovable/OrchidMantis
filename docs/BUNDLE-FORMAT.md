# BUNDLE-FORMAT — `zkpox-2.0` CBOR schema reference

The bundle is a single CBOR document, encoded with ciborium. Maps use
text-string keys (CBOR major type 3); byte fields are CBOR byte strings
(major type 2); integers are CBOR integers (major types 0/1).

## Canonical encoding for hashing

Two hashes are derived from the bundle and travel separately:

1. `bundle_hash_pre_timestamp(bundle)` — hash with `timestamp = None`.
   The Rekor anchor binds this hash to its log entry.
2. `bundle_hash_pre_researcher(bundle)` — hash with `timestamp = None`
   AND `researcher = None`. The researcher signs this hash.

Both use ciborium's default encoder; map ordering is determined by
struct field order (Rust definitions), which is stable across builds.
Adding a field requires re-deriving both hashes (and is therefore a
wire-breaking change without an explicit migration plan).

## Top-level fields

```
{
  "version":         "zkpox-2.0",            (Text)
  "experimental":    true / false,           (Bool)
  "target":          Target,
  "predicate":       Predicate,
  "backend":         Backend,
  "proof":           Proof,
  "vendor_envelope": VendorEnvelope,
  "timestamp":       Timestamp | absent,
  "researcher":      Researcher | absent
}
```

## `Target`

```
{
  "kind":       "c-source" | "elf-rv64im" | "llvm-ir" | ...,    (Text)
  "hash":       "sha256:<64 hex chars>",                         (Text)
  "url":        URL string | absent,                             (Text)
  "source_url": URL string | absent,                             (Text)
  "metadata":   { String → CBOR Value }                          (Map)
}
```

- `hash` is the sha256 of the canonical target bytes (for c-source: the
  file contents). Cross-checked against `PublicValues.target_hash`.
- `kind` decides which backends accept the target. v0.1 only ships
  `c-source` (static-c backend).
- `url` is informational. Verifiers MUST NOT use it as the trust root
  — pass `--target <local path>` to re-hash.
- `metadata` is free-form (`buf_size`, `entry_symbol`, CVE id, etc.).
  Not committed to the proof.

## `Predicate`

```
{
  "id":            "memory-safety::oob-write",     (Text)
  "id_canonical":  0x0000_0002,                    (Unsigned int)
  "version":       1,                              (Unsigned int)
  "outputs":       Predicate-specific CBOR Value   (Any)
}
```

- `id` MUST match the canonical name in `zkpox-schema::registry`.
- `id_canonical` MUST equal `predicate_id(id)`. Cross-checked against
  `PublicValues.predicate_id`.
- `version` MUST match `PublicValues.predicate_version`.
- `outputs` is informational — verifiers re-decode the canonical
  `outputs_bytes` from the proof's public values and compare; mismatch
  is a hard failure.

## `Backend`

```
{
  "kind":                 "static-c" | "riscv-emu" | "llvm-interp",     (Text)
  "id_canonical":         0x0000_0001,                                   (Unsigned int)
  "version":              1,                                             (Unsigned int)
  "verifier_key_digest":  "sha256:<64 hex chars>"                       (Text)
}
```

- `verifier_key_digest` is the SP1 verifying-key fingerprint
  (`bytes32_raw()` of the VK). The verifier re-derives this from the
  guest ELF cached for the (target_hash, predicate, sp1_zkvm_version)
  tuple and rejects bundles whose digest doesn't match.

## `Proof`

```
{
  "system":         "sp1-stark-core/v6.0.1" | "sp1-groth16-bn254/v6.0.1",  (Text)
  "bytes":          <bytes>,                                                (Byte string)
  "public_values":  <bytes>                                                 (Byte string)
}
```

- `bytes` is what `sp1-sdk`'s `proof.save(...)` produces — pass back
  into the SDK via `SP1ProofWithPublicValues::load(...)`.
- `public_values` is the canonical encoding of the public values; the
  verifier reads back the same fields from the proof itself and
  compares. Exposed separately so the verifier can render a human-
  readable summary without re-loading the entire proof.

## Public-values layout (committed by the guest)

Reading order (each line is one commit call inside the guest):

```
1.  version            : u32   (PUBLIC_VALUES_VERSION)
2.  target_hash        : [u8; 32]
3.  predicate_id       : u32
4.  predicate_version  : u32
5.  backend_id         : u32
6.  backend_version    : u32
7.  flags              : u32   ((inv_flag << 0) | (vuln_flag << 1))
8.  outputs_len        : u32
9.  outputs_bytes      : [u8; outputs_len]
```

The host reads in this exact order. Changing the order or adding a
field requires bumping `PUBLIC_VALUES_VERSION`.

## `VendorEnvelope`

```
{
  "scheme":                    "zkpox-aes256gcm+age+tlock-drand-quicknet/v1" | "zkpox-none/v1",
  "aes_blob":                  <bytes>,       (Byte string — 12-byte nonce || AES-GCM ct+tag)
  "ct_k_age":                  <bytes>,
  "ct_k_tlock":                <bytes>,
  "drand_round_min":           u64 | absent,
  "vendor_pubkey":             "age1...",     (Text)
  "vendor_pubkey_fingerprint": "sha256:<64 hex chars>"  (Text)
}
```

- `aes_blob` is the witness encrypted under a random 32-byte key `K`.
  AAD is the constant string `zkpox-envelope-v1`.
- `ct_k_age` is `K` encrypted to the vendor's age recipient (X25519).
- `ct_k_tlock` is `K` encrypted to the Drand quicknet round
  `drand_round_min` via `tlock_age::encrypt`. The tlock blob is
  self-contained and embeds the chain hash + round.
- `scheme == "zkpox-none/v1"` indicates no envelope (the witness
  travels out-of-band or there is no privacy requirement). All
  ciphertext fields are empty in that case.

## `Timestamp`

```
{
  "rekor_log_index":             u64,
  "rekor_log_id":                "<hex>",                       (Text)
  "integrated_time":             i64,                           (Unix seconds)
  "entry_uuid":                  "<hex>",                       (Text)
  "inclusion_proof_root_hash":   "<hex>",                       (Text)
  "inclusion_proof_tree_size":   u64,
  "inclusion_proof_hashes":      ["<hex>", "<hex>", ...]        (Array of Text)
  "signed_entry_timestamp":      "<base64>" | absent            (Text)
}
```

`signed_entry_timestamp` is the Rekor v1 **SET** — base64 of the
log's own signature over the canonical
`{body, integratedTime, logIndex, logID}` JSON. Optional: absent on
self-hosted logs that don't emit one, and on bundles produced before
this field existed. The verifier also re-fetches it from Rekor at
verify time, so the field is a convenience cache, not a trust root.

Verifier checks (with network, single fetch):

1. Fetch entry by `rekor_log_index`. Decode its base64 `body`.
2. Compare the body's `data.hash` to `bundle_hash_pre_timestamp(bundle)`.
3. Reconstruct the Merkle leaf as `sha256(0x00 || body_bytes)`.
4. Walk the path via `inclusion_proof_hashes`; verify the result
   matches `inclusion_proof_root_hash`.
5. If `zkpox-verify --rekor-pubkey <PEM>` is supplied, verify the
   entry's Signed Entry Timestamp against that key (ECDSA P-256 for
   the public Sigstore Rekor, or Ed25519 for self-hosted logs). This
   proves the log endorsed the entry, not just that an inclusion proof
   reconstructs. Without the key the SET check is skipped.

## `Researcher`

```
{
  "pubkey":                <bytes>,    (PEM-encoded ed25519 SPKI)
  "signature_over_bundle": <bytes>,    (ed25519 signature, 64 bytes)
  "contact":               "email or URL" | absent
}
```

- The signature is over `bundle_hash_pre_researcher(bundle)`.
- `pubkey` is PEM-encoded so it can be copy-pasted into other tools
  (gpg, openssl, sigstore).
- Anonymous mode omits the `researcher` field entirely; priority is
  then established by the Rekor timestamp alone.
