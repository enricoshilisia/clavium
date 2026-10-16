//! Asymmetric key wrapping — the mechanism behind a shared (organization)
//! vault's key hierarchy.
//!
//! A shared vault's own symmetric key is generated once, independent of
//! any single member's password (no one person's forgotten password
//! should be able to lock out a team vault). To grant a device access,
//! that key is wrapped — RSA-OAEP, a textbook, non-novel scheme, not
//! something invented for this product — under the device's own public
//! key. The server stores only these wrapped copies and the public keys
//! that produced them; neither tells it anything about the private keys
//! needed to open them, which is what lets it move wrapped keys around on
//! a grant or discard them on a revoke without ever being trusted with
//! vault contents itself.

use rand::rngs::OsRng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Result, VaultError};

/// AES-256 key length — a shared vault's key is wrapped, not derived, so
/// it is exactly the key size the vault format's own cipher needs.
pub const SHARED_KEY_LEN: usize = 32;

const RSA_BITS: usize = 2048;

/// One device's own asymmetric keypair. The private half is never sent
/// anywhere — only [`DeviceKeypair::public_key_der`] ever crosses the
/// network, which is safe by construction: a public key reveals nothing
/// about what it can decrypt.
pub struct DeviceKeypair {
    private: RsaPrivateKey,
    public: RsaPublicKey,
}

impl DeviceKeypair {
    /// A fresh RSA-2048 keypair. Generated once per device, the first time
    /// it opts into organization-shared vaults — not something a person
    /// waits on repeatedly.
    pub fn generate() -> Result<Self> {
        let private = RsaPrivateKey::new(&mut OsRng, RSA_BITS)
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
        let public = RsaPublicKey::from(&private);
        Ok(Self { private, public })
    }

    pub fn public_key_der(&self) -> Result<Vec<u8>> {
        self.public
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))
    }

    /// The private key, as PKCS#8 DER — for this device's own local
    /// storage only. What exactly protects it at rest (an OS keychain, a
    /// locally-derived key) is a decision for the layer that calls this,
    /// not this crate; its job stops at "do not hand this out by
    /// accident", which is why there is no path that serializes it
    /// anywhere other than an explicit call to this function.
    pub fn private_key_der(&self) -> Result<Vec<u8>> {
        self.private
            .to_pkcs8_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))
    }

    pub fn from_private_key_der(der: &[u8]) -> Result<Self> {
        let private = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
        let public = RsaPublicKey::from(&private);
        Ok(Self { private, public })
    }

    /// Unwrap a shared vault key that was wrapped for this device's
    /// public key. Fails the same generic way for a key wrapped for a
    /// different device, or for tampered ciphertext — an unwrap is not an
    /// oracle for telling the two apart, matching the vault format's own
    /// refusal to distinguish "wrong password" from "corrupt file".
    pub fn unwrap_key(&self, wrapped: &[u8]) -> Result<[u8; SHARED_KEY_LEN]> {
        let padding = Oaep::new::<Sha256>();
        let mut raw = self
            .private
            .decrypt(padding, wrapped)
            .map_err(|_| VaultError::Decryption)?;

        if raw.len() != SHARED_KEY_LEN {
            raw.zeroize();
            return Err(VaultError::Decryption);
        }
        let mut key = [0u8; SHARED_KEY_LEN];
        key.copy_from_slice(&raw);
        raw.zeroize();
        Ok(key)
    }
}

/// A fresh random key for a brand-new shared vault.
pub fn generate_shared_key() -> [u8; SHARED_KEY_LEN] {
    use rand::RngCore;
    let mut key = [0u8; SHARED_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Wrap a shared vault's key for one recipient device, needing only that
/// device's public key — the operation that makes "grant access" safe to
/// run anywhere, including on a server that must never hold a private
/// key: it has everything this function needs and nothing it would take
/// to reverse it.
pub fn wrap_key_for_device(public_key_der: &[u8], key: &[u8; SHARED_KEY_LEN]) -> Result<Vec<u8>> {
    let public = RsaPublicKey::from_public_key_der(public_key_der)
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
    let padding = Oaep::new::<Sha256>();
    public
        .encrypt(&mut OsRng, padding, key.as_slice())
        .map_err(|e| VaultError::Encryption(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_wrapped_for_a_device_unwraps_to_the_same_key() {
        let device = DeviceKeypair::generate().unwrap();
        let key = generate_shared_key();

        let wrapped = wrap_key_for_device(&device.public_key_der().unwrap(), &key).unwrap();
        let unwrapped = device.unwrap_key(&wrapped).unwrap();

        assert_eq!(unwrapped, key);
    }

    #[test]
    fn a_key_wrapped_for_one_device_cannot_be_unwrapped_by_another() {
        let recipient = DeviceKeypair::generate().unwrap();
        let eavesdropper = DeviceKeypair::generate().unwrap();
        let key = generate_shared_key();

        let wrapped = wrap_key_for_device(&recipient.public_key_der().unwrap(), &key).unwrap();

        assert!(eavesdropper.unwrap_key(&wrapped).is_err());
        assert_eq!(recipient.unwrap_key(&wrapped).unwrap(), key);
    }

    #[test]
    fn tampered_wrapped_key_bytes_fail_to_unwrap() {
        let device = DeviceKeypair::generate().unwrap();
        let key = generate_shared_key();
        let mut wrapped = wrap_key_for_device(&device.public_key_der().unwrap(), &key).unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0xFF;

        assert!(device.unwrap_key(&wrapped).is_err());
    }

    #[test]
    fn wrapping_the_same_key_twice_produces_different_ciphertext() {
        // OAEP is randomized padding — two wraps of the same key for the
        // same device must not be comparable byte-for-byte, the same
        // "never a fingerprint of unchanged content" property the vault
        // file format itself guarantees for re-saves.
        let device = DeviceKeypair::generate().unwrap();
        let key = generate_shared_key();
        let public_der = device.public_key_der().unwrap();

        let a = wrap_key_for_device(&public_der, &key).unwrap();
        let b = wrap_key_for_device(&public_der, &key).unwrap();

        assert_ne!(a, b);
        assert_eq!(device.unwrap_key(&a).unwrap(), key);
        assert_eq!(device.unwrap_key(&b).unwrap(), key);
    }

    #[test]
    fn a_private_key_round_trips_through_der_encoding() {
        // The path a device takes restoring its own keypair from local
        // storage between launches — if this silently produced a
        // different key, every shared vault the device had access to
        // would become unreadable without a word of warning why.
        let original = DeviceKeypair::generate().unwrap();
        let der = original.private_key_der().unwrap();
        let restored = DeviceKeypair::from_private_key_der(&der).unwrap();

        let key = generate_shared_key();
        let wrapped = wrap_key_for_device(&original.public_key_der().unwrap(), &key).unwrap();
        assert_eq!(restored.unwrap_key(&wrapped).unwrap(), key);
    }
}
