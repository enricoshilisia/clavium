//! QR device linking: a signed-in, unlocked device hands the vault key to
//! a new device without the server being able to read or forge it.
//!
//! 1. The new device makes a one-time X25519 key pair and a random 16-byte
//!    link secret. It registers only the public key with the server and
//!    shows `public key + link secret` in a QR code.
//! 2. The approving device scans the QR, makes its own one-time key pair,
//!    and derives an AES-256-GCM key with HKDF over the X25519 shared
//!    secret, salted with the link secret (which the server never sees).
//! 3. It encrypts `{vault_id, vault_key}` and sends it via the server.
//! 4. The new device derives the same key and decrypts.
//!
//! The server knows both public keys but not the link secret, so it can
//! neither decrypt the payload nor substitute its own (a forged payload
//! fails authentication).

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{decrypt_with_aad, encrypt_with_aad, NONCE_LEN};
use crate::error::{Result, VaultError};
use crate::keyring::VAULT_KEY_LEN;

pub const LINK_SECRET_LEN: usize = 16;

/// Held by the new device while it waits for approval. Never serialized.
pub struct LinkRequest {
    secret: StaticSecret,
    pub public_key: [u8; 32],
    pub link_secret: [u8; LINK_SECRET_LEN],
}

/// What the approving device sends back (through the server).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkEnvelope {
    pub sender_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct LinkPayload {
    vault_id: Uuid,
    vault_key: String,
}

fn derive(shared: &[u8; 32], link_secret: &[u8], receiver_pub: &[u8; 32], sender_pub: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(link_secret), shared);
    let mut info = b"clavium-link-v1|".to_vec();
    info.extend_from_slice(receiver_pub);
    info.extend_from_slice(sender_pub);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, key.as_mut()).expect("valid HKDF length");
    key
}

fn aad(receiver_pub: &[u8; 32], sender_pub: &[u8; 32]) -> Vec<u8> {
    let mut a = b"clavium-link-v1".to_vec();
    a.extend_from_slice(receiver_pub);
    a.extend_from_slice(sender_pub);
    a
}

fn decode32(s: &str) -> Result<[u8; 32]> {
    let v = B64URL.decode(s.trim()).map_err(|_| VaultError::LinkInvalid)?;
    v.try_into().map_err(|_| VaultError::LinkInvalid)
}

/// A short code both screens can show so a person can confirm they are
/// linking the device in front of them. Derived from the QR contents.
pub fn verification_code(public_key: &[u8; 32], link_secret: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"clavium-link-code");
    h.update(public_key);
    h.update(link_secret);
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

impl LinkRequest {
    pub fn new() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret).to_bytes();
        let mut link_secret = [0u8; LINK_SECRET_LEN];
        OsRng.fill_bytes(&mut link_secret);
        Self { secret, public_key, link_secret }
    }

    pub fn public_key_b64(&self) -> String {
        B64URL.encode(self.public_key)
    }

    pub fn link_secret_b64(&self) -> String {
        B64URL.encode(self.link_secret)
    }

    pub fn verification_code(&self) -> String {
        verification_code(&self.public_key, &self.link_secret)
    }

    /// Open the approving device's envelope: the vault id and key.
    pub fn open(&self, env: &LinkEnvelope) -> Result<(Uuid, Zeroizing<[u8; VAULT_KEY_LEN]>)> {
        let sender = decode32(&env.sender_public_key)?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(sender));
        let key = derive(shared.as_bytes(), &self.link_secret, &self.public_key, &sender);
        let nonce_v = B64URL.decode(&env.nonce).map_err(|_| VaultError::LinkInvalid)?;
        let nonce: [u8; NONCE_LEN] = nonce_v.try_into().map_err(|_| VaultError::LinkInvalid)?;
        let ct = B64URL.decode(&env.ciphertext).map_err(|_| VaultError::LinkInvalid)?;
        let plain = Zeroizing::new(
            decrypt_with_aad(&key, &ct, &nonce, &aad(&self.public_key, &sender)).map_err(|_| VaultError::LinkInvalid)?,
        );
        let payload: LinkPayload = serde_json::from_slice(&plain).map_err(|_| VaultError::LinkInvalid)?;
        let raw = Zeroizing::new(base64::engine::general_purpose::STANDARD.decode(&payload.vault_key).map_err(|_| VaultError::LinkInvalid)?);
        let mut k = Zeroizing::new([0u8; VAULT_KEY_LEN]);
        if raw.len() != VAULT_KEY_LEN {
            return Err(VaultError::LinkInvalid);
        }
        k.copy_from_slice(&raw);
        Ok((payload.vault_id, k))
    }
}

impl Default for LinkRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// On the approving device: encrypt `vault_key` for the device whose QR
/// code carried `receiver_public_key` and `link_secret` (both base64url).
pub fn seal_for_link(
    receiver_public_key: &str,
    link_secret: &str,
    vault_id: Uuid,
    vault_key: &[u8; VAULT_KEY_LEN],
) -> Result<LinkEnvelope> {
    let receiver = decode32(receiver_public_key)?;
    let secret = B64URL.decode(link_secret.trim()).map_err(|_| VaultError::LinkInvalid)?;
    if secret.len() != LINK_SECRET_LEN {
        return Err(VaultError::LinkInvalid);
    }
    let mine = StaticSecret::random_from_rng(OsRng);
    let sender = PublicKey::from(&mine).to_bytes();
    let shared = mine.diffie_hellman(&PublicKey::from(receiver));
    let key = derive(shared.as_bytes(), &secret, &receiver, &sender);
    let payload = Zeroizing::new(serde_json::to_vec(&LinkPayload {
        vault_id,
        vault_key: base64::engine::general_purpose::STANDARD.encode(vault_key),
    })?);
    let (ct, nonce) = encrypt_with_aad(&key, &payload, &aad(&receiver, &sender))?;
    Ok(LinkEnvelope {
        sender_public_key: B64URL.encode(sender),
        nonce: B64URL.encode(nonce),
        ciphertext: B64URL.encode(ct),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_new_device_recovers_the_vault_key() {
        let req = LinkRequest::new();
        let vid = Uuid::new_v4();
        let key = [7u8; 32];
        let env = seal_for_link(&req.public_key_b64(), &req.link_secret_b64(), vid, &key).unwrap();
        let (got_id, got_key) = req.open(&env).unwrap();
        assert_eq!(got_id, vid);
        assert_eq!(*got_key, key);
    }

    #[test]
    fn without_the_link_secret_a_server_cannot_forge_a_payload() {
        // The server knows the public key, not the secret from the QR.
        let req = LinkRequest::new();
        let wrong_secret = B64URL.encode([0u8; LINK_SECRET_LEN]);
        let forged = seal_for_link(&req.public_key_b64(), &wrong_secret, Uuid::new_v4(), &[1u8; 32]).unwrap();
        assert!(matches!(req.open(&forged), Err(VaultError::LinkInvalid)));
    }

    #[test]
    fn another_device_cannot_open_the_envelope() {
        let req = LinkRequest::new();
        let other = LinkRequest::new();
        let env = seal_for_link(&req.public_key_b64(), &req.link_secret_b64(), Uuid::new_v4(), &[3u8; 32]).unwrap();
        assert!(other.open(&env).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let req = LinkRequest::new();
        let mut env = seal_for_link(&req.public_key_b64(), &req.link_secret_b64(), Uuid::new_v4(), &[3u8; 32]).unwrap();
        let mut ct = B64URL.decode(&env.ciphertext).unwrap();
        ct[0] ^= 1;
        env.ciphertext = B64URL.encode(ct);
        assert!(req.open(&env).is_err());
    }

    #[test]
    fn verification_codes_match_on_both_sides() {
        let req = LinkRequest::new();
        let pk = decode32(&req.public_key_b64()).unwrap();
        let s = B64URL.decode(req.link_secret_b64()).unwrap();
        assert_eq!(verification_code(&pk, &s), req.verification_code());
        assert_eq!(req.verification_code().len(), 7);
    }
}
