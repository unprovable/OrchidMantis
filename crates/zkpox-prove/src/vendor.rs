//! Vendor age-recipient resolution.
//!
//! A disclosure bundle's vendor envelope is encrypted to the vendor's
//! `age1…` recipient. Pasting that recipient in by hand
//! (`--vendor-pubkey`) leaves nothing in the bundle tying it to the
//! vendor — a producer could substitute any key. `--vendor-from-domain`
//! instead resolves the recipient from a location the vendor controls
//! and records *where* it came from, so a reviewer can trace the key
//! back to a published source.
//!
//! Resolution order for `<domain>`:
//!   1. `https://<domain>/.well-known/security.txt` — a
//!      `Zkpox-Age-Recipient:` field (a zkpox convention extending
//!      RFC 9116). Method `"security.txt"`.
//!   2. `https://<domain>/.well-known/zkpox-vendor.age.pub` — a
//!      dedicated file whose body is the bare `age1…` recipient.
//!      Method `"well-known-file"`.
//!
//! HTTPS only; an `http://` resolution is refused (the whole point is a
//! trustworthy channel to the vendor).

use anyhow::{bail, Context, Result};

/// A vendor recipient plus the provenance of how it was obtained.
#[derive(Debug, Clone)]
pub struct ResolvedVendor {
    /// The `age1…` recipient the envelope is sealed to.
    pub recipient: String,
    /// URL the recipient was fetched from, or `None` when supplied raw
    /// via `--vendor-pubkey`.
    pub source_url: Option<String>,
    /// `"security.txt"` | `"well-known-file"`, or `None` for a raw key.
    pub source_method: Option<String>,
}

impl ResolvedVendor {
    /// A recipient supplied directly on the CLI — no source provenance.
    pub fn from_raw(recipient: String) -> Self {
        Self {
            recipient,
            source_url: None,
            source_method: None,
        }
    }

    /// No vendor envelope requested.
    pub fn none() -> Self {
        Self {
            recipient: String::new(),
            source_url: None,
            source_method: None,
        }
    }
}

/// Validate the shape of an age X25519 recipient (`age1` + bech32 body).
/// We don't decode bech32 here — `age::x25519::Recipient::from_str`
/// (called by the envelope crate) is the authority — but a cheap prefix
/// check catches a fetched blob that obviously isn't a recipient.
fn looks_like_age_recipient(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("age1") && s.len() >= 20 && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Resolve a vendor recipient from `domain`. Tries security.txt first,
/// then the dedicated well-known file.
pub fn resolve_from_domain(domain: &str) -> Result<ResolvedVendor> {
    let domain = domain.trim().trim_end_matches('/');
    if domain.contains("://") && !domain.starts_with("https://") {
        bail!("--vendor-from-domain must be a bare domain or an https:// URL, got {domain:?}");
    }
    // Accept either a bare domain ("vendor.example") or a full
    // "https://vendor.example" — normalise to host for URL building.
    let host = domain.trim_start_matches("https://");

    let sec_url = format!("https://{host}/.well-known/security.txt");
    if let Some(rec) = try_security_txt(&sec_url)? {
        return Ok(ResolvedVendor {
            recipient: rec,
            source_url: Some(sec_url),
            source_method: Some("security.txt".to_string()),
        });
    }

    let file_url = format!("https://{host}/.well-known/zkpox-vendor.age.pub");
    if let Some(rec) = try_well_known_file(&file_url)? {
        return Ok(ResolvedVendor {
            recipient: rec,
            source_url: Some(file_url),
            source_method: Some("well-known-file".to_string()),
        });
    }

    bail!(
        "could not resolve a vendor age recipient for {host}: no `Zkpox-Age-Recipient` field in \
         {sec_url} and no {file_url}. Ask the vendor to publish one, or pass --vendor-pubkey."
    )
}

/// Fetch `url` and return its body, or `None` on a 404 (so the caller
/// can fall through to the next resolution method). Other HTTP/transport
/// errors are fatal.
fn fetch_optional(url: &str) -> Result<Option<String>> {
    match ureq::get(url).call() {
        Ok(resp) => {
            let body = resp
                .into_string()
                .with_context(|| format!("reading body of {url}"))?;
            Ok(Some(body))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            bail!("fetching {url}: HTTP {code}: {body}");
        }
        Err(e) => bail!("fetching {url}: {e}"),
    }
}

/// Parse a `Zkpox-Age-Recipient:` field out of a security.txt body.
fn try_security_txt(url: &str) -> Result<Option<String>> {
    let Some(body) = fetch_optional(url)? else {
        return Ok(None);
    };
    for line in body.lines() {
        let line = line.trim();
        // Case-insensitive field name per RFC 9116 §2.4.
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("Zkpox-Age-Recipient") {
                let rec = value.trim().to_string();
                if !looks_like_age_recipient(&rec) {
                    bail!(
                        "{url} has a Zkpox-Age-Recipient field but its value {rec:?} is not an \
                         age1… recipient"
                    );
                }
                return Ok(Some(rec));
            }
        }
    }
    Ok(None)
}

/// Read a dedicated `.well-known/zkpox-vendor.age.pub` whose body is the
/// bare recipient (ignoring blank lines and `#` comments).
fn try_well_known_file(url: &str) -> Result<Option<String>> {
    let Some(body) = fetch_optional(url)? else {
        return Ok(None);
    };
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !looks_like_age_recipient(line) {
            bail!("{url} body {line:?} is not an age1… recipient");
        }
        return Ok(Some(line.to_string()));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_shape_check() {
        assert!(looks_like_age_recipient(
            "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
        ));
        assert!(!looks_like_age_recipient("not-a-key"));
        assert!(!looks_like_age_recipient("ssh-ed25519 AAAA"));
        assert!(!looks_like_age_recipient(""));
    }

    #[test]
    fn https_required() {
        let e = resolve_from_domain("http://vendor.example").unwrap_err();
        assert!(e.to_string().contains("https"));
    }
}
