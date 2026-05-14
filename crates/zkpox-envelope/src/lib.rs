//! # zkpox-envelope
//!
//! Pure-Rust port of RAPTOR's `packages/zkpox/envelope.py`. No
//! subprocess shell-outs to `age` / `tle` binaries — instead, the
//! `age` Rust crate for the vendor recipient path and `tlock_age` for
//! the Drand time-lock path.
//!
//! ## Layered encryption
//!
//! ```text
//!   witness bytes
//!         │
//!         ▼   K = random 32 bytes
//!   AES-256-GCM
//!         │
//!         ▼ (aes_blob = nonce(12) || ciphertext || tag)
//!     (witness sealed under K)
//!
//!   K
//!   ├─────────▶ age encrypt to vendor recipient   ▶  ct_K_age      (vendor path)
//!   └─────────▶ tlock_age encrypt to Drand round  ▶  ct_K_tlock    (public path)
//! ```
//!
//! Two independent recovery paths:
//!
//! 1. **Vendor path** — vendor decrypts `ct_K_age` with their age
//!    secret key to recover `K`, then AES-GCM-decrypts `aes_blob`.
//! 2. **Time-lock path** — once the Drand quicknet round `R`
//!    finalises, anyone fetches the round's BLS signature from a
//!    Drand HTTP endpoint and uses `tlock_age::decrypt` to recover
//!    `K`, then AES-GCM-decrypts `aes_blob`.
//!
//! ## Drand network identity
//!
//! Hardcoded to Drand's **quicknet** chain (3-second period,
//! unchained BLS-on-G1 signing). This is the network the `tle` CLI
//! defaults to, and matches what RAPTOR's MVP used. The chain
//! identifiers are public:
//!
//! - `chain_hash`: `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`
//! - `period`: 3 seconds
//! - `genesis_time`: 1692803367 (Unix epoch, 2023-08-23)
//! - `public_key`: see `DRAND_QUICKNET_PUBLIC_KEY` below.

use std::io::Cursor;

use age::secrecy::ExposeSecret;
use rand::RngCore;

use zkpox_schema::ENVELOPE_AAD;

pub use zkpox_schema::ENVELOPE_SCHEME;

/// Errors raised by the envelope.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("AES key must be 32 bytes (got {0})")]
    BadAesKeyLen(usize),

    #[error("AES-GCM blob too short to contain a 12-byte nonce")]
    BlobTooShort,

    #[error("AES-GCM operation failed (likely AAD mismatch or tampered ciphertext)")]
    AesGcm,

    #[error("age encryption: {0}")]
    AgeEncrypt(String),

    #[error("age decryption: {0}")]
    AgeDecrypt(String),

    #[error("age recipient parse: {0:?}")]
    AgeRecipient(String),

    #[error("tlock_age encryption: {0}")]
    TlockEncrypt(String),

    #[error("tlock_age decryption: {0}")]
    TlockDecrypt(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = core::result::Result<T, EnvelopeError>;

/// Three-blob layered envelope produced by `seal_envelope`.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// 12-byte nonce concatenated with AES-256-GCM ciphertext+tag.
    pub aes_blob: Vec<u8>,
    /// age-encrypted symmetric key K. Vendor recovery path.
    pub ct_k_age: Vec<u8>,
    /// tlock_age-encrypted symmetric key K. Public-after-round path.
    pub ct_k_tlock: Vec<u8>,
    /// The Drand quicknet round number the tlock blob targets.
    pub drand_round: u64,
}

// --- Drand quicknet pinned parameters ---------------------------------

/// Drand quicknet chain hash. Hex-decoded from
/// `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`.
pub const DRAND_QUICKNET_CHAIN_HASH: [u8; 32] = [
    0x52, 0xdb, 0x9b, 0xa7, 0x0e, 0x0c, 0xc0, 0xf6, 0xea, 0xf7, 0x80, 0x3d, 0xd0, 0x74, 0x47, 0xa1,
    0xf5, 0x47, 0x77, 0x35, 0xfd, 0x3f, 0x66, 0x17, 0x92, 0xba, 0x94, 0x60, 0x0c, 0x84, 0xe9, 0x71,
];

/// Drand quicknet round-period in seconds.
pub const DRAND_QUICKNET_PERIOD: u64 = 3;

/// Drand quicknet genesis time (Unix seconds). Round 1 is finalised
/// at `genesis_time + period * 1`.
pub const DRAND_QUICKNET_GENESIS_TIME: u64 = 1_692_803_367;

/// Drand quicknet group BLS public key (compressed G2). Hex-decoded
/// from the value published at https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info
/// — quicknet uses BLS on G1 for signatures and G2 for the group key,
/// 96 compressed bytes.
pub const DRAND_QUICKNET_PUBLIC_KEY: [u8; 96] = [
    0x83, 0xcf, 0x0f, 0x28, 0x96, 0xad, 0xee, 0x7e, 0xb8, 0xb5, 0xf0, 0x1f, 0xca, 0xd3, 0x91, 0x29,
    0x12, 0xc6, 0x29, 0x67, 0x12, 0xf7, 0x95, 0x09, 0x9c, 0x09, 0x4f, 0x97, 0x4c, 0xee, 0xd2, 0xf3,
    0x55, 0xc2, 0xb6, 0x7c, 0xb5, 0x65, 0xb1, 0xe7, 0xf3, 0xfa, 0xc8, 0x4e, 0xbf, 0x10, 0x5a, 0xbc,
    0xc8, 0x86, 0x8c, 0xc8, 0xe1, 0xab, 0x2c, 0xe8, 0xd3, 0x84, 0xe5, 0x14, 0x1c, 0x95, 0xe8, 0x63,
    0x35, 0x6a, 0xeb, 0xa2, 0xf3, 0x21, 0x2f, 0xff, 0x82, 0x4f, 0x7d, 0xa3, 0xdf, 0x44, 0xbe, 0x44,
    0xfa, 0xcc, 0xf9, 0x9a, 0xb1, 0xb7, 0xdf, 0xbd, 0x68, 0xe6, 0xf2, 0xb1, 0x3d, 0xfd, 0xee, 0x9e,
];

/// Compute the Drand quicknet round that finalises closest to (but
/// not before) `unix_seconds`. Used to translate a duration ("90d
/// from now") into a concrete round number.
pub fn round_at(unix_seconds: u64) -> u64 {
    if unix_seconds <= DRAND_QUICKNET_GENESIS_TIME {
        return 1;
    }
    let elapsed = unix_seconds - DRAND_QUICKNET_GENESIS_TIME;
    // Ceiling division — we want the FIRST round at or after that time.
    (elapsed + DRAND_QUICKNET_PERIOD - 1) / DRAND_QUICKNET_PERIOD + 1
}

/// Parse a Go-style duration string ("90d", "30m", "8s") into
/// seconds. Subset of Go's `time.ParseDuration` — enough to cover
/// "Ns", "Nm", "Nh", "Nd". RAPTOR's wrapper accepts these same units
/// so a producer migrating across the two tools sees identical
/// behaviour.
pub fn parse_duration_seconds(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num_part, unit) = match s.chars().last()? {
        c @ ('s' | 'm' | 'h' | 'd') => (&s[..s.len() - 1], c),
        _ => return None,
    };
    let n: u64 = num_part.parse().ok()?;
    Some(match unit {
        's' => n,
        'm' => n * 60,
        'h' => n * 60 * 60,
        'd' => n * 60 * 60 * 24,
        _ => unreachable!(),
    })
}

// --- AES-256-GCM ------------------------------------------------------

/// Encrypt `plaintext` under a 32-byte `key`. Returns nonce(12) ||
/// ciphertext-with-tag, bound to `ENVELOPE_AAD` so blobs from other
/// protocols can't be replayed through us.
pub fn aes_encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    if key.len() != 32 {
        return Err(EnvelopeError::BadAesKeyLen(key.len()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EnvelopeError::AesGcm)?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: ENVELOPE_AAD,
            },
        )
        .map_err(|_| EnvelopeError::AesGcm)?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of `aes_encrypt`.
pub fn aes_decrypt(blob: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    if key.len() != 32 {
        return Err(EnvelopeError::BadAesKeyLen(key.len()));
    }
    if blob.len() < 12 {
        return Err(EnvelopeError::BlobTooShort);
    }
    let nonce = Nonce::from_slice(&blob[..12]);
    let ct = &blob[12..];
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EnvelopeError::AesGcm)?;
    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ct,
                aad: ENVELOPE_AAD,
            },
        )
        .map_err(|_| EnvelopeError::AesGcm)
}

// --- age (vendor recipient path) --------------------------------------

/// Encrypt `plaintext` to a single age recipient (`age1...` X25519
/// pubkey). The output is the binary age envelope; verifiers do not
/// need to know the age format to handle it as opaque bytes.
pub fn age_encrypt_to(plaintext: &[u8], recipient: &str) -> Result<Vec<u8>> {
    use std::io::Write;
    let r: age::x25519::Recipient = recipient
        .parse()
        .map_err(|e: &str| EnvelopeError::AgeRecipient(e.to_string()))?;
    let recipients: Vec<&dyn age::Recipient> = vec![&r];
    let enc = age::Encryptor::with_recipients(recipients.into_iter())
        .map_err(|e| EnvelopeError::AgeEncrypt(e.to_string()))?;
    let mut out = Vec::with_capacity(plaintext.len() + 256);
    {
        let mut w = enc
            .wrap_output(&mut out)
            .map_err(|e| EnvelopeError::AgeEncrypt(e.to_string()))?;
        w.write_all(plaintext)?;
        w.finish()
            .map_err(|e| EnvelopeError::AgeEncrypt(e.to_string()))?;
    }
    Ok(out)
}

/// Decrypt an age blob with an X25519 identity (`AGE-SECRET-KEY-1...`).
///
/// The age v0.11 API exposes a refusal path for passphrase-wrapped
/// blobs via `Decryptor::is_scrypt()`; we use that to fail loudly if
/// the bundle was sealed with a passphrase rather than an X25519
/// recipient. Our envelope only ever produces X25519-wrapped blobs.
pub fn age_decrypt_with_identity(blob: &[u8], identity_str: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let identity: age::x25519::Identity = identity_str
        .parse()
        .map_err(|e: &str| EnvelopeError::AgeRecipient(e.to_string()))?;
    let dec = age::Decryptor::new(blob)
        .map_err(|e| EnvelopeError::AgeDecrypt(e.to_string()))?;
    if dec.is_scrypt() {
        return Err(EnvelopeError::AgeDecrypt(
            "envelope expects an X25519 recipient, found passphrase wrapping".into(),
        ));
    }
    let mut out = Vec::with_capacity(blob.len());
    {
        let mut r = dec
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|e| EnvelopeError::AgeDecrypt(e.to_string()))?;
        r.read_to_end(&mut out)?;
    }
    Ok(out)
}

/// Generate a fresh ephemeral age X25519 keypair. The secret should
/// be kept by whoever needs to play the vendor role in a test;
/// production vendors use their published keys.
pub fn gen_ephemeral_age_keypair() -> (String, String) {
    let id = age::x25519::Identity::generate();
    let recipient = id.to_public().to_string();
    let secret = id.to_string().expose_secret().to_string();
    (secret, recipient)
}

// --- tlock_age (Drand quicknet path) ----------------------------------

/// Encrypt `plaintext` so it can be decrypted only after Drand
/// quicknet round `round` finalises. The plaintext is wrapped in an
/// age header with the tlock metadata embedded — the resulting blob
/// is self-contained and needs only the Drand round's BLS signature
/// at decrypt time.
pub fn tlock_encrypt(plaintext: &[u8], round: u64) -> Result<Vec<u8>> {
    let src = Cursor::new(plaintext);
    let mut dst = Vec::with_capacity(plaintext.len() + 512);
    tlock_age::encrypt(
        &mut dst,
        src,
        &DRAND_QUICKNET_CHAIN_HASH,
        &DRAND_QUICKNET_PUBLIC_KEY,
        round,
    )
    .map_err(|e| EnvelopeError::TlockEncrypt(format!("{e:?}")))?;
    Ok(dst)
}

/// Inverse of `tlock_encrypt`. The caller must fetch
/// `drand_round_signature` from a Drand HTTP endpoint (e.g.
/// `https://api.drand.sh/{chain_hash}/public/{round}`) once the round
/// has finalised; this function does no network I/O.
pub fn tlock_decrypt(blob: &[u8], drand_round_signature: &[u8]) -> Result<Vec<u8>> {
    let src = Cursor::new(blob);
    let mut dst = Vec::with_capacity(blob.len());
    tlock_age::decrypt(
        &mut dst,
        src,
        &DRAND_QUICKNET_CHAIN_HASH,
        drand_round_signature,
    )
    .map_err(|e| EnvelopeError::TlockDecrypt(format!("{e:?}")))?;
    Ok(dst)
}

// --- High-level seal --------------------------------------------------

/// Produce the layered envelope for a witness.
///
/// `vendor_pubkey` is an `age1...` X25519 recipient. `duration` is a
/// Go-style duration string (`"90d"`, `"30s"`, ...) interpreted as
/// "lock until at least this far in the future." The returned
/// `drand_round` is informational — the bundle records it so humans
/// can grep, but the tlock blob itself binds the round
/// cryptographically.
pub fn seal_envelope(
    witness: &[u8],
    vendor_pubkey: &str,
    duration: &str,
) -> Result<Envelope> {
    let dur_s = parse_duration_seconds(duration).ok_or_else(|| {
        EnvelopeError::TlockEncrypt(format!("invalid duration {duration:?}"))
    })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| EnvelopeError::TlockEncrypt(format!("system clock pre-1970? {e}")))?
        .as_secs();
    let target_time = now.saturating_add(dur_s);
    let round = round_at(target_time);
    seal_envelope_at_round(witness, vendor_pubkey, round)
}

/// Like `seal_envelope` but caller supplies an explicit Drand round.
/// Tests use this to avoid coupling to the wall-clock.
pub fn seal_envelope_at_round(
    witness: &[u8],
    vendor_pubkey: &str,
    drand_round: u64,
) -> Result<Envelope> {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    let aes_blob = aes_encrypt(witness, &k)?;
    let ct_k_age = age_encrypt_to(&k, vendor_pubkey)?;
    let ct_k_tlock = tlock_encrypt(&k, drand_round)?;
    Ok(Envelope {
        aes_blob,
        ct_k_age,
        ct_k_tlock,
        drand_round,
    })
}

/// Recover the witness via the vendor's age secret key.
pub fn open_via_vendor(envelope: &Envelope, vendor_identity: &str) -> Result<Vec<u8>> {
    let k = age_decrypt_with_identity(&envelope.ct_k_age, vendor_identity)?;
    aes_decrypt(&envelope.aes_blob, &k)
}

/// Recover the witness via the Drand round signature (post-round).
pub fn open_via_tlock(envelope: &Envelope, drand_round_signature: &[u8]) -> Result<Vec<u8>> {
    let k = tlock_decrypt(&envelope.ct_k_tlock, drand_round_signature)?;
    aes_decrypt(&envelope.aes_blob, &k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_round_trip() {
        let key = [0x42; 32];
        let pt = b"the quick brown fox jumps over the lazy dog";
        let blob = aes_encrypt(pt, &key).unwrap();
        let out = aes_decrypt(&blob, &key).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn aes_rejects_tampered_blob() {
        let key = [0x42; 32];
        let pt = b"secret";
        let mut blob = aes_encrypt(pt, &key).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(aes_decrypt(&blob, &key).is_err());
    }

    #[test]
    fn age_vendor_round_trip() {
        let (secret, recipient) = gen_ephemeral_age_keypair();
        let pt = b"vendor-readable witness";
        let blob = age_encrypt_to(pt, &recipient).unwrap();
        let out = age_decrypt_with_identity(&blob, &secret).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn vendor_path_seals_and_opens() {
        let (secret, recipient) = gen_ephemeral_age_keypair();
        let witness = b"my exploit input bytes";
        // Round number is arbitrary for the vendor-path test —
        // tlock_age::encrypt does not network, it just embeds round
        // metadata. We never call tlock_decrypt here.
        let env = seal_envelope_at_round(witness, &recipient, 99_999_999).unwrap();
        let out = open_via_vendor(&env, &secret).unwrap();
        assert_eq!(out, witness);
    }

    #[test]
    fn parse_duration_handles_all_units() {
        assert_eq!(parse_duration_seconds("8s"), Some(8));
        assert_eq!(parse_duration_seconds("3m"), Some(180));
        assert_eq!(parse_duration_seconds("2h"), Some(7200));
        assert_eq!(parse_duration_seconds("90d"), Some(60 * 60 * 24 * 90));
        assert_eq!(parse_duration_seconds("garbage"), None);
        assert_eq!(parse_duration_seconds(""), None);
    }

    #[test]
    fn round_at_genesis_is_one() {
        assert_eq!(round_at(DRAND_QUICKNET_GENESIS_TIME), 1);
    }

    #[test]
    fn round_at_after_genesis_advances() {
        let one_minute = DRAND_QUICKNET_GENESIS_TIME + 60;
        assert_eq!(round_at(one_minute), 21); // (60+2)/3 + 1 = 21
    }
}
