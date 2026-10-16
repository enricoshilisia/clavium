//! HOTP (RFC 4226) and TOTP (RFC 6238) — the Authenticator's actual job.
//! Standards-compliant on purpose: the whole point is that a code this
//! crate generates is accepted by Microsoft 365, Google, GitHub, or
//! anything else that speaks the same standard, not a scheme of our own.
//!
//! Correctness here is tested against RFC 4226 Appendix D's own published
//! HOTP vectors (quoted below, not re-derived) rather than against
//! RFC 6238's TOTP-specific decimal outputs — TOTP is defined as HOTP
//! keyed by a time-derived counter, so anchoring tests on the HOTP
//! vectors and then checking that derivation (`totp_at` at a given time
//! equals `hotp` at the matching counter) verifies both the HMAC
//! truncation and the time-to-counter math without needing a second,
//! independently-recalled set of magic numbers.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Result, VaultError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl OtpAlgorithm {
    fn parse(name: &str) -> Self {
        // An unrecognized algorithm name in a scanned otpauth:// URI falls
        // back to SHA1 — the default every authenticator app and issuer
        // assumes when the parameter is absent, so this is "assume the
        // default", not "silently guess".
        match name.to_ascii_uppercase().as_str() {
            "SHA256" => Self::Sha256,
            "SHA512" => Self::Sha512,
            _ => Self::Sha1,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TotpParams {
    /// Decoded secret bytes — never the Base32 text form once parsed.
    pub secret: Vec<u8>,
    pub algorithm: OtpAlgorithm,
    pub digits: u32,
    pub period_seconds: u64,
}

impl Default for TotpParams {
    fn default() -> Self {
        Self {
            secret: Vec::new(),
            algorithm: OtpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
        }
    }
}

/// RFC 4226's dynamic truncation (§5.3), applied to a raw HMAC digest:
/// the low nibble of the last byte picks a 4-byte window, whose top bit
/// is masked off so the result never looks negative when read as a
/// signed int in another implementation.
fn truncate(digest: &[u8], digits: u32) -> String {
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let window = [
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ];
    let code = u32::from_be_bytes(window);
    let modulus = 10u32.pow(digits);
    format!("{:0width$}", code % modulus, width = digits as usize)
}

/// One HOTP code for `secret` at `counter`, under the given algorithm.
/// Each branch is the same three lines under a different concrete
/// `Hmac<D>` — kept as separate branches rather than one generic
/// function so the HMAC crate's own trait bounds never have to be
/// re-stated here.
pub fn hotp(secret: &[u8], counter: u64, algorithm: OtpAlgorithm, digits: u32) -> Result<String> {
    let counter_bytes = counter.to_be_bytes();
    let digest: Vec<u8> = match algorithm {
        OtpAlgorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(secret)
                .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(secret)
                .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };
    Ok(truncate(&digest, digits))
}

/// The TOTP code `params` produces at a specific Unix time — the form
/// every test in this module actually exercises, so a wrong-clock bug
/// can be tested deterministically instead of racing the real clock.
pub fn totp_at(params: &TotpParams, unix_time: u64) -> Result<String> {
    let counter = unix_time / params.period_seconds;
    hotp(&params.secret, counter, params.algorithm, params.digits)
}

/// The TOTP code right now — what the Authenticator UI actually shows.
pub fn totp_now(params: &TotpParams) -> Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?
        .as_secs();
    totp_at(params, now)
}

/// Seconds remaining in the current period — what a countdown ring in
/// the UI animates against.
pub fn seconds_remaining(params: &TotpParams, unix_time: u64) -> u64 {
    params.period_seconds - (unix_time % params.period_seconds)
}

/// What a vault record's own `totp_secret` field actually holds — either
/// a full `otpauth://totp/...` URI (pasted whole, or recovered from a
/// scanned QR code) or a bare Base32 secret (what every issuer also
/// shows as plain text, for when scanning isn't possible). Accepting
/// both is what makes "paste your 2FA secret" actually match what a
/// real enrollment screen hands someone.
pub fn parse_secret_or_uri(input: &str) -> Result<TotpParams> {
    let trimmed = input.trim();
    if trimmed.starts_with("otpauth://") {
        let (_, params) = parse_otpauth_uri(trimmed)?;
        Ok(params)
    } else {
        Ok(TotpParams {
            secret: base32_decode(trimmed)?,
            ..TotpParams::default()
        })
    }
}

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 Base32 decode — every TOTP secret arrives this way (it's
/// what a scanned `otpauth://` QR code's `secret` parameter is), so this
/// is a correctness utility, not a security boundary: no secret ever
/// needs to round-trip through this crate undecoded.
pub fn base32_decode(input: &str) -> Result<Vec<u8>> {
    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .map(|b| b.to_ascii_uppercase())
        .collect();

    let mut bits: u64 = 0;
    let mut bit_count = 0u32;
    let mut out = Vec::with_capacity(cleaned.len() * 5 / 8);

    for byte in cleaned {
        let value = BASE32_ALPHABET
            .iter()
            .position(|&c| c == byte)
            .ok_or_else(|| VaultError::KeyDerivation(format!("invalid Base32 character: {}", byte as char)))?;
        bits = (bits << 5) | value as u64;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }
    Ok(out)
}

/// Parse a scanned `otpauth://totp/...` URI into a label and the
/// parameters needed to generate codes from it. Defaults match every
/// major issuer's own assumption when a parameter is left out: SHA1,
/// 6 digits, a 30-second period.
pub fn parse_otpauth_uri(uri: &str) -> Result<(String, TotpParams)> {
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .ok_or_else(|| VaultError::KeyDerivation("not an otpauth://totp/ URI".to_string()))?;

    let (label_part, query_part) = rest
        .split_once('?')
        .ok_or_else(|| VaultError::KeyDerivation("otpauth URI has no query parameters".to_string()))?;
    let label = urlencoding_decode(label_part);

    let mut params = TotpParams::default();
    let mut secret_found = false;

    for pair in query_part.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let value = urlencoding_decode(value);
        match key {
            "secret" => {
                params.secret = base32_decode(&value)?;
                secret_found = true;
            }
            "algorithm" => params.algorithm = OtpAlgorithm::parse(&value),
            "digits" => {
                params.digits = value
                    .parse()
                    .map_err(|_| VaultError::KeyDerivation("invalid digits parameter".to_string()))?;
            }
            "period" => {
                params.period_seconds = value
                    .parse()
                    .map_err(|_| VaultError::KeyDerivation("invalid period parameter".to_string()))?;
            }
            _ => {}
        }
    }

    if !secret_found {
        return Err(VaultError::KeyDerivation("otpauth URI has no secret parameter".to_string()));
    }
    Ok((label, params))
}

/// Minimal percent-decoding — otpauth URIs only ever escape the label
/// (issuer/account names), never binary data, so this never needs to be
/// more than ASCII-safe.
fn urlencoding_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(value) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
                out.push(value);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4226 Appendix D's own published HOTP test vectors: secret is
    /// the ASCII string "12345678901234567890", SHA1, 6 digits.
    const RFC4226_SECRET: &[u8] = b"12345678901234567890";
    const RFC4226_VECTORS: [(u64, &str); 10] = [
        (0, "755224"),
        (1, "287082"),
        (2, "359152"),
        (3, "969429"),
        (4, "338314"),
        (5, "254676"),
        (6, "287922"),
        (7, "162583"),
        (8, "399871"),
        (9, "520489"),
    ];

    #[test]
    fn hotp_matches_every_rfc4226_test_vector() {
        for (counter, expected) in RFC4226_VECTORS {
            let code = hotp(RFC4226_SECRET, counter, OtpAlgorithm::Sha1, 6).unwrap();
            assert_eq!(code, expected, "counter {counter}");
        }
    }

    #[test]
    fn totp_reduces_to_hotp_at_the_matching_time_step() {
        // T0=0, period=30s: time in [0,30) -> counter 0, [30,60) -> counter 1.
        let params = TotpParams {
            secret: RFC4226_SECRET.to_vec(),
            algorithm: OtpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
        };
        assert_eq!(totp_at(&params, 0).unwrap(), "755224");
        assert_eq!(totp_at(&params, 29).unwrap(), "755224");
        assert_eq!(totp_at(&params, 30).unwrap(), "287082");
        assert_eq!(totp_at(&params, 59).unwrap(), "287082");
        assert_eq!(totp_at(&params, 60).unwrap(), "359152");
    }

    #[test]
    fn seconds_remaining_counts_down_within_a_period() {
        let params = TotpParams { period_seconds: 30, ..Default::default() };
        assert_eq!(seconds_remaining(&params, 0), 30);
        assert_eq!(seconds_remaining(&params, 1), 29);
        assert_eq!(seconds_remaining(&params, 29), 1);
        assert_eq!(seconds_remaining(&params, 30), 30);
    }

    #[test]
    fn different_algorithms_produce_different_codes_for_the_same_input() {
        let a = hotp(RFC4226_SECRET, 0, OtpAlgorithm::Sha1, 6).unwrap();
        let b = hotp(RFC4226_SECRET, 0, OtpAlgorithm::Sha256, 6).unwrap();
        let c = hotp(RFC4226_SECRET, 0, OtpAlgorithm::Sha512, 6).unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn eight_digit_codes_are_zero_padded_to_eight_characters() {
        let code = hotp(RFC4226_SECRET, 0, OtpAlgorithm::Sha1, 8).unwrap();
        assert_eq!(code.len(), 8);
    }

    #[test]
    fn base32_decodes_a_known_value() {
        // "Hello!" in Base32, verified against a reference encoder.
        let decoded = base32_decode("JBSWY3DPEE======").unwrap();
        assert_eq!(decoded, b"Hello!");
    }

    #[test]
    fn base32_decode_rejects_invalid_characters() {
        assert!(base32_decode("not-valid-base32!!!").is_err());
    }

    #[test]
    fn base32_decode_is_case_insensitive_and_ignores_padding_and_whitespace() {
        let a = base32_decode("JBSWY3DPEE======").unwrap();
        let b = base32_decode("jbswy3dpee").unwrap();
        let c = base32_decode("JBSW Y3DP EE").unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn parses_a_real_shaped_otpauth_uri() {
        let uri = "otpauth://totp/Clavium:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Clavium&algorithm=SHA1&digits=6&period=30";
        let (label, params) = parse_otpauth_uri(uri).unwrap();
        assert_eq!(label, "Clavium:alice@example.com");
        assert_eq!(params.algorithm, OtpAlgorithm::Sha1);
        assert_eq!(params.digits, 6);
        assert_eq!(params.period_seconds, 30);
        assert!(!params.secret.is_empty());
    }

    #[test]
    fn parses_an_otpauth_uri_with_defaults_when_parameters_are_omitted() {
        let uri = "otpauth://totp/GitHub:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let (_, params) = parse_otpauth_uri(uri).unwrap();
        assert_eq!(params.algorithm, OtpAlgorithm::Sha1);
        assert_eq!(params.digits, 6);
        assert_eq!(params.period_seconds, 30);
    }

    #[test]
    fn a_non_otpauth_uri_is_refused() {
        assert!(parse_otpauth_uri("https://example.com").is_err());
    }

    #[test]
    fn an_otpauth_uri_with_no_secret_is_refused() {
        assert!(parse_otpauth_uri("otpauth://totp/X?issuer=X").is_err());
    }

    #[test]
    fn parse_secret_or_uri_accepts_a_bare_base32_secret() {
        let params = parse_secret_or_uri("JBSWY3DPEE======").unwrap();
        assert_eq!(params.secret, b"Hello!");
        assert_eq!(params.algorithm, OtpAlgorithm::Sha1);
        assert_eq!(params.digits, 6);
    }

    #[test]
    fn parse_secret_or_uri_accepts_a_full_otpauth_uri() {
        let params =
            parse_secret_or_uri("otpauth://totp/X:y?secret=JBSWY3DPEE======&digits=8").unwrap();
        assert_eq!(params.secret, b"Hello!");
        assert_eq!(params.digits, 8);
    }

    #[test]
    fn a_real_otpauth_uri_produces_codes_matching_direct_hotp_computation() {
        // Cross-check the whole pipeline: parse -> generate must equal
        // decoding the same secret and calling hotp() directly.
        let uri = "otpauth://totp/Test:acct?secret=JBSWY3DPEE======&digits=6&period=30";
        let (_, params) = parse_otpauth_uri(uri).unwrap();
        let via_parse = totp_at(&params, 12345).unwrap();
        let via_direct = totp_at(
            &TotpParams { secret: b"Hello!".to_vec(), ..TotpParams::default() },
            12345,
        )
        .unwrap();
        assert_eq!(via_parse, via_direct);
    }
}
