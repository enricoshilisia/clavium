//! Share links: send one item to anyone, without the server being able to
//! read it.
//!
//! The app encrypts the item with a fresh random key and uploads only the
//! ciphertext. The key travels in the link's `#fragment`, which browsers
//! never send to a server. The recipient's browser decrypts it with
//! WebCrypto in a plain web page; they need no app and no account.
//!
//! Optional passphrase (told to the recipient another way, e.g. by phone):
//! mixed into the key with PBKDF2-SHA256 (600 000 rounds), so the link
//! alone opens nothing.
//!
//! The server only hands out the ciphertext to someone who proves they
//! hold the full key (`auth`), so a person who merely saw the share id
//! cannot use up its views, and a wrong passphrase is counted.
//!
//! Exact construction (the web page mirrors it in JavaScript):
//!   link_key  = 32 random bytes (base64url in the fragment)
//!   ikm       = link_key, or link_key || PBKDF2-SHA256(passphrase, salt, 600000, 32)
//!   enc_key   = HKDF-SHA256(ikm, salt = "clavium-share-v1", info = "enc")
//!   auth      = HKDF-SHA256(ikm, salt = "clavium-share-v1", info = "auth")
//!   server keeps SHA-256(auth) (hex); AES-256-GCM with
//!   AAD = "clavium-share-v1|" + share id (lowercase, hyphenated)

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{decrypt_with_aad, encrypt_with_aad, NONCE_LEN};
use crate::error::{Result, VaultError};

pub const PBKDF2_ROUNDS: u32 = 600_000;

/// What a recipient sees, as JSON. The 2FA secret is left out unless the
/// sender asks: it is usually better to set up 2FA again than to copy it.
pub fn payload_for(record: &crate::record::Record, include_totp: bool) -> serde_json::Value {
    serde_json::json!({
        "v": 1,
        "kind": record.kind,
        "title": record.title,
        "username": record.username,
        "password": record.password,
        "url": record.url,
        "notes": record.notes,
        "fields": record.fields.iter().map(|(k, v)| serde_json::json!({ "name": k, "value": v })).collect::<Vec<_>>(),
        "custom_fields": record.custom_fields,
        "totp_secret": if include_totp { record.totp_secret.clone() } else { None },
    })
}

pub fn payload_for_text(title: &str, text: &str) -> serde_json::Value {
    serde_json::json!({ "v": 1, "kind": "secure_note", "title": title, "notes": text })
}

/// What the app uploads (everything except `link_key`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareDraft {
    pub id: Uuid,
    pub nonce: String,
    pub ciphertext: String,
    /// base64 16-byte PBKDF2 salt; empty without a passphrase.
    pub salt: String,
    /// hex SHA-256 of `auth`.
    pub auth_hash: String,
    /// base64url key for the link fragment. Never uploaded.
    pub link_key: String,
}

fn aad(id: Uuid) -> Vec<u8> {
    format!("clavium-share-v1|{}", id.hyphenated()).into_bytes()
}

fn keys(link_key: &[u8], passphrase: Option<&str>, salt: &[u8], rounds: u32) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut ikm = Zeroizing::new(link_key.to_vec());
    if let Some(p) = passphrase.map(str::trim).filter(|p| !p.is_empty()) {
        let mut stretched = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha256>(p.as_bytes(), salt, rounds, stretched.as_mut());
        ikm.extend_from_slice(stretched.as_ref());
    }
    let hk = Hkdf::<Sha256>::new(Some(b"clavium-share-v1"), &ikm);
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut auth = Zeroizing::new([0u8; 32]);
    hk.expand(b"enc", enc.as_mut()).expect("valid length");
    hk.expand(b"auth", auth.as_mut()).expect("valid length");
    (enc, auth)
}

pub fn auth_hash(auth: &[u8]) -> String {
    Sha256::digest(auth).iter().map(|b| format!("{b:02x}")).collect()
}

/// Encrypt `payload` (JSON of the shared item) for a new share link.
pub fn create(payload: &[u8], passphrase: Option<&str>) -> Result<ShareDraft> {
    create_with_rounds(payload, passphrase, PBKDF2_ROUNDS)
}

pub fn create_with_rounds(payload: &[u8], passphrase: Option<&str>, rounds: u32) -> Result<ShareDraft> {
    let passphrase = passphrase.map(str::trim).filter(|p| !p.is_empty());
    let id = Uuid::new_v4();
    let mut link_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(link_key.as_mut());
    let mut salt = [0u8; 16];
    if passphrase.is_some() {
        OsRng.fill_bytes(&mut salt);
    }
    let (enc, auth) = keys(link_key.as_ref(), passphrase, &salt, rounds);
    let (ct, nonce) = encrypt_with_aad(&enc, payload, &aad(id))?;
    Ok(ShareDraft {
        id,
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ct),
        salt: if passphrase.is_some() { B64.encode(salt) } else { String::new() },
        auth_hash: auth_hash(auth.as_ref()),
        link_key: B64URL.encode(link_key.as_ref()),
    })
}

/// The recipient side (the web page does the same in JavaScript; this is
/// used by tests and could be used by an app that opens links itself).
pub fn open(id: Uuid, link_key_b64url: &str, passphrase: Option<&str>, salt_b64: &str, nonce_b64: &str, ciphertext_b64: &str) -> Result<Vec<u8>> {
    open_with_rounds(id, link_key_b64url, passphrase, salt_b64, nonce_b64, ciphertext_b64, PBKDF2_ROUNDS)
}

pub fn open_with_rounds(id: Uuid, link_key_b64url: &str, passphrase: Option<&str>, salt_b64: &str, nonce_b64: &str, ciphertext_b64: &str, rounds: u32) -> Result<Vec<u8>> {
    let link_key = Zeroizing::new(B64URL.decode(link_key_b64url.trim()).map_err(|_| VaultError::Decryption)?);
    let salt = if salt_b64.is_empty() { vec![0u8; 16] } else { B64.decode(salt_b64).map_err(|_| VaultError::Decryption)? };
    let passphrase = if salt_b64.is_empty() { None } else { passphrase };
    let (enc, _) = keys(&link_key, passphrase, &salt, rounds);
    let nonce: [u8; NONCE_LEN] = B64.decode(nonce_b64).ok().and_then(|n| n.try_into().ok()).ok_or(VaultError::Decryption)?;
    let ct = B64.decode(ciphertext_b64).map_err(|_| VaultError::Decryption)?;
    decrypt_with_aad(&enc, &ct, &nonce, &aad(id)).map_err(|_| VaultError::Decryption)
}

/// The `auth` value a recipient sends to the server to fetch the ciphertext.
pub fn auth_for(link_key_b64url: &str, passphrase: Option<&str>, salt_b64: &str, rounds: u32) -> Result<String> {
    let link_key = Zeroizing::new(B64URL.decode(link_key_b64url.trim()).map_err(|_| VaultError::Decryption)?);
    let salt = if salt_b64.is_empty() { vec![0u8; 16] } else { B64.decode(salt_b64).map_err(|_| VaultError::Decryption)? };
    let (_, auth) = keys(&link_key, if salt_b64.is_empty() { None } else { passphrase }, &salt, rounds);
    Ok(B64URL.encode(auth.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_without_and_with_passphrase() {
        let d = create_with_rounds(br#"{"title":"Wi-Fi"}"#, None, 1000).unwrap();
        assert!(d.salt.is_empty());
        assert_eq!(open_with_rounds(d.id, &d.link_key, None, &d.salt, &d.nonce, &d.ciphertext, 1000).unwrap(), br#"{"title":"Wi-Fi"}"#);
        // The id is bound in: a ciphertext moved to another id fails.
        assert!(open_with_rounds(Uuid::new_v4(), &d.link_key, None, &d.salt, &d.nonce, &d.ciphertext, 1000).is_err());

        let p = create_with_rounds(b"secret", Some("blue horse"), 1000).unwrap();
        assert_eq!(open_with_rounds(p.id, &p.link_key, Some("blue horse"), &p.salt, &p.nonce, &p.ciphertext, 1000).unwrap(), b"secret");
        assert!(open_with_rounds(p.id, &p.link_key, Some("red horse"), &p.salt, &p.nonce, &p.ciphertext, 1000).is_err());
        assert!(open_with_rounds(p.id, &p.link_key, None, &p.salt, &p.nonce, &p.ciphertext, 1000).is_err());
        // The server can check auth without learning the key.
        let auth = auth_for(&p.link_key, Some("blue horse"), &p.salt, 1000).unwrap();
        assert_eq!(auth_hash(&B64URL.decode(auth).unwrap()), p.auth_hash);
        let wrong = auth_for(&p.link_key, Some("red horse"), &p.salt, 1000).unwrap();
        assert_ne!(auth_hash(&B64URL.decode(wrong).unwrap()), p.auth_hash);
    }

    /// Fixed vector so the JavaScript page can be checked against it.
    #[test]
    fn auth_matches_the_documented_construction() {
        let key = B64URL.encode([7u8; 32]);
        let salt = B64.encode([9u8; 16]);
        let auth = auth_for(&key, Some("pass"), &salt, 1000).unwrap();
        assert_eq!(auth.len(), 43);
        assert_eq!(auth_for(&key, None, "", 1000).unwrap(), auth_for(&key, Some("ignored"), "", 1000).unwrap());
    }
}
