//! Authenticated encryption of a vault's contents. AES-256-GCM via
//! RustCrypto's own `aes-gcm` crate — never a hand-rolled cipher mode, and
//! never encryption without authentication: a tampered ciphertext must
//! fail to decrypt, not decrypt into garbage nobody notices.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

use crate::error::{Result, VaultError};
use crate::kdf::DerivedKey;

pub const NONCE_LEN: usize = 12;

/// Encrypt `plaintext` under `key`, with a freshly generated nonce. The
/// nonce is returned alongside the ciphertext — it is not a secret, it
/// only ever needs to be unique per encryption under one key, which a
/// fresh random 96-bit value gives with a negligible collision chance for
/// the number of times one vault is ever re-saved.
pub fn encrypt(key: &DerivedKey, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let cipher =
        Aes256Gcm::new_from_slice(&key.0).map_err(|e| VaultError::Encryption(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt `ciphertext`, verifying its authentication tag before
/// returning anything. A wrong key or a tampered ciphertext both surface
/// as the same `Decryption` error — deliberately not distinguished, so a
/// vault file cannot be used as an oracle for guessing which byte of an
/// attacker's tampering was detected.
pub fn decrypt(key: &DerivedKey, ciphertext: &[u8], nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(&key.0).map_err(|e| VaultError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{derive_key, generate_salt, KdfParams};

    fn test_key() -> DerivedKey {
        derive_key("test password", &generate_salt(), &KdfParams::default()).unwrap()
    }

    #[test]
    fn encrypting_then_decrypting_returns_the_original_plaintext() {
        let key = test_key();
        let plaintext = b"the quick brown fox";
        let (ciphertext, nonce) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn the_wrong_key_fails_to_decrypt_rather_than_returning_garbage() {
        let key = test_key();
        let wrong_key = test_key();
        let (ciphertext, nonce) = encrypt(&key, b"secret").unwrap();
        let result = decrypt(&wrong_key, &ciphertext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn a_tampered_ciphertext_fails_to_decrypt() {
        let key = test_key();
        let (mut ciphertext, nonce) = encrypt(&key, b"secret message").unwrap();
        ciphertext[0] ^= 0xFF; // flip a bit
        let result = decrypt(&key, &ciphertext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn a_tampered_authentication_tag_fails_to_decrypt() {
        let key = test_key();
        let (mut ciphertext, nonce) = encrypt(&key, b"secret message").unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF; // the tag is appended at the end by aes-gcm
        let result = decrypt(&key, &ciphertext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn two_encryptions_of_the_same_plaintext_use_different_nonces() {
        let key = test_key();
        let (_, nonce_a) = encrypt(&key, b"same message").unwrap();
        let (_, nonce_b) = encrypt(&key, b"same message").unwrap();
        assert_ne!(nonce_a, nonce_b);
    }
}
