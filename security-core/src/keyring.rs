//! The vault key and the "key slots" that unlock it.
//!
//! A v3 vault is encrypted under one random 256-bit vault key. That key is
//! never derived from anything a person types: it is stored wrapped
//! (AES-256-GCM) once per slot, and each slot has its own way of producing
//! the wrapping key:
//!
//! - `password`: Argon2id over the master password (salt + params stored).
//! - `prf`: HKDF-SHA256 over a passkey's WebAuthn PRF output, so a passkey
//!   can unlock the vault without the master password.
//! - `recovery`: HKDF-SHA256 over a random recovery key shown once.
//!
//! Consequences: changing the master password rewrites one slot, not the
//! vault; adding passkey unlock adds a slot; and a device holding the
//! unwrapped vault key can save without keeping the master password around.
//!
//! Every wrapped key is authenticated with the vault id and slot id as
//! AAD, so a slot cannot be copied from one vault into another.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{decrypt_with_aad, encrypt_with_aad, NONCE_LEN};
use crate::error::{Result, VaultError};
use crate::kdf::{derive_key, generate_salt, KdfParams, SALT_LEN};

pub const VAULT_KEY_LEN: usize = 32;
pub type VaultKey = Zeroizing<[u8; VAULT_KEY_LEN]>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SlotKind {
    Password,
    Prf,
    Recovery,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeySlot {
    pub id: Uuid,
    pub kind: SlotKind,
    /// Shown in settings ("MacBook passkey", "Printed recovery key").
    #[serde(default)]
    pub label: String,
    /// Password slots: Argon2id salt (base64) and parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<KdfParams>,
    /// PRF slots: the WebAuthn credential id (base64url, as the browser
    /// gives it) so a client knows which passkey to ask for, and the PRF
    /// salt it must evaluate (base64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf_salt: Option<String>,
    pub nonce: String,
    pub wrapped_key: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// The public, non-secret half of a v3 vault: its id and its slots. This
/// is what the header of a vault file holds, and what the control plane
/// stores so a brand-new device can unlock and then pull records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyringHeader {
    pub vault_id: Uuid,
    pub slots: Vec<KeySlot>,
}

/// A header plus the unwrapped vault key, held only while unlocked.
#[derive(Clone)]
pub struct Keyring {
    pub header: KeyringHeader,
    key: VaultKey,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("header", &self.header)
            .field("key", &"<redacted>")
            .finish()
    }
}

fn random_key() -> VaultKey {
    let mut k = Zeroizing::new([0u8; VAULT_KEY_LEN]);
    rand::thread_rng().fill_bytes(k.as_mut());
    k
}

fn slot_aad(vault_id: Uuid, slot_id: Uuid) -> Vec<u8> {
    let mut aad = b"clavium-slot-v1|".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(slot_id.as_bytes());
    aad
}

fn hkdf_key(input: &[u8], info: &[u8]) -> VaultKey {
    let hk = Hkdf::<Sha256>::new(Some(b"clavium-keyslot"), input);
    let mut out = Zeroizing::new([0u8; VAULT_KEY_LEN]);
    hk.expand(info, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

fn b64d(s: &str) -> Result<Vec<u8>> {
    B64.decode(s).map_err(|_| VaultError::IncorrectPasswordOrCorruptFile)
}

/// A recovery key as shown to a person: 32 random bytes, base32 in groups
/// of four, e.g. `ABCD-EFGH-...`. Formatting is ignored when typed back.
pub fn generate_recovery_key() -> Zeroizing<String> {
    let mut raw = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut raw);
    let encoded = crate::otp::base32_encode(&raw);
    let grouped: Vec<String> = encoded
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    Zeroizing::new(grouped.join("-"))
}

fn normalize_recovery_key(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

impl Keyring {
    /// A brand-new vault key with one password slot.
    pub fn new_with_password(master_password: &str, params: KdfParams) -> Result<Self> {
        let mut ring = Keyring {
            header: KeyringHeader {
                vault_id: Uuid::new_v4(),
                slots: Vec::new(),
            },
            key: random_key(),
        };
        ring.add_password_slot(master_password, params, "Master password")?;
        Ok(ring)
    }

    /// A keyring whose key arrived by QR device linking. The caller must
    /// already have checked the vault id; the key is then proven by the
    /// first record it decrypts (every item is AES-GCM authenticated).
    pub fn from_linked_key(header: KeyringHeader, key: VaultKey) -> Self {
        Keyring { header, key }
    }

    pub fn key(&self) -> &[u8; VAULT_KEY_LEN] {
        &self.key
    }

    pub fn vault_id(&self) -> Uuid {
        self.header.vault_id
    }

    fn wrap(&self, slot_id: Uuid, wrapping_key: &[u8; 32]) -> Result<(String, String)> {
        let (ct, nonce) = encrypt_with_aad(
            wrapping_key,
            self.key.as_ref(),
            &slot_aad(self.header.vault_id, slot_id),
        )?;
        Ok((B64.encode(nonce), B64.encode(ct)))
    }

    fn unwrap_slot(header: &KeyringHeader, slot: &KeySlot, wrapping_key: &[u8; 32]) -> Result<VaultKey> {
        let nonce_vec = b64d(&slot.nonce)?;
        if nonce_vec.len() != NONCE_LEN {
            return Err(VaultError::IncorrectPasswordOrCorruptFile);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_vec);
        let plain = Zeroizing::new(
            decrypt_with_aad(
                wrapping_key,
                &b64d(&slot.wrapped_key)?,
                &nonce,
                &slot_aad(header.vault_id, slot.id),
            )
            .map_err(|_| VaultError::IncorrectPasswordOrCorruptFile)?,
        );
        if plain.len() != VAULT_KEY_LEN {
            return Err(VaultError::IncorrectPasswordOrCorruptFile);
        }
        let mut key = Zeroizing::new([0u8; VAULT_KEY_LEN]);
        key.copy_from_slice(&plain);
        Ok(key)
    }

    pub fn add_password_slot(&mut self, password: &str, params: KdfParams, label: &str) -> Result<Uuid> {
        let salt = generate_salt();
        let derived = derive_key(password, &salt, &params)?;
        let id = Uuid::new_v4();
        let (nonce, wrapped_key) = self.wrap(id, &derived.0)?;
        self.header.slots.push(KeySlot {
            id,
            kind: SlotKind::Password,
            label: label.to_string(),
            salt: Some(B64.encode(salt)),
            kdf: Some(params),
            credential_id: None,
            prf_salt: None,
            nonce,
            wrapped_key,
            created_at: chrono::Utc::now(),
        });
        Ok(id)
    }

    /// Add passkey unlock. `prf_output` is the 32-byte result of the
    /// WebAuthn PRF extension evaluated with `prf_salt` for this
    /// credential; it is never stored.
    pub fn add_prf_slot(
        &mut self,
        credential_id: &str,
        prf_salt: &[u8],
        prf_output: &[u8],
        label: &str,
    ) -> Result<Uuid> {
        if prf_output.len() < 32 {
            return Err(VaultError::KeyDerivation("PRF output must be at least 32 bytes".into()));
        }
        let id = Uuid::new_v4();
        let wrapping = hkdf_key(prf_output, b"prf");
        let (nonce, wrapped_key) = self.wrap(id, &wrapping)?;
        self.header.slots.push(KeySlot {
            id,
            kind: SlotKind::Prf,
            label: label.to_string(),
            salt: None,
            kdf: None,
            credential_id: Some(credential_id.to_string()),
            prf_salt: Some(B64.encode(prf_salt)),
            nonce,
            wrapped_key,
            created_at: chrono::Utc::now(),
        });
        Ok(id)
    }

    /// Add a recovery-key slot and return the key to show the person once.
    pub fn add_recovery_slot(&mut self, label: &str) -> Result<(Uuid, Zeroizing<String>)> {
        let recovery = generate_recovery_key();
        let id = Uuid::new_v4();
        let wrapping = hkdf_key(normalize_recovery_key(&recovery).as_bytes(), b"recovery");
        let (nonce, wrapped_key) = self.wrap(id, &wrapping)?;
        self.header.slots.push(KeySlot {
            id,
            kind: SlotKind::Recovery,
            label: label.to_string(),
            salt: None,
            kdf: None,
            credential_id: None,
            prf_salt: None,
            nonce,
            wrapped_key,
            created_at: chrono::Utc::now(),
        });
        Ok((id, recovery))
    }

    /// Remove a slot. Refuses to remove the last password slot, so a vault
    /// can never end up openable only by a passkey that might be lost.
    pub fn remove_slot(&mut self, slot_id: Uuid) -> Result<()> {
        let slot = self
            .header
            .slots
            .iter()
            .find(|s| s.id == slot_id)
            .ok_or(VaultError::SlotNotFound)?;
        let password_slots = self
            .header
            .slots
            .iter()
            .filter(|s| s.kind == SlotKind::Password)
            .count();
        if slot.kind == SlotKind::Password && password_slots == 1 {
            return Err(VaultError::LastPasswordSlot);
        }
        self.header.slots.retain(|s| s.id != slot_id);
        Ok(())
    }

    /// Replace every password slot with one for `new_password`. Other
    /// slots (passkeys, recovery) keep working: the vault key is unchanged.
    pub fn change_password(&mut self, new_password: &str, params: KdfParams) -> Result<()> {
        let new_id = self.add_password_slot(new_password, params, "Master password")?;
        self.header
            .slots
            .retain(|s| s.kind != SlotKind::Password || s.id == new_id);
        Ok(())
    }

    pub fn unlock_with_password(header: KeyringHeader, password: &str) -> Result<Self> {
        for slot in header.slots.iter().filter(|s| s.kind == SlotKind::Password) {
            let (Some(salt_b64), Some(params)) = (&slot.salt, &slot.kdf) else {
                continue;
            };
            let salt_vec = b64d(salt_b64)?;
            if salt_vec.len() != SALT_LEN {
                continue;
            }
            let mut salt = [0u8; SALT_LEN];
            salt.copy_from_slice(&salt_vec);
            let derived = derive_key(password, &salt, params)
                .map_err(|_| VaultError::IncorrectPasswordOrCorruptFile)?;
            if let Ok(key) = Self::unwrap_slot(&header, slot, &derived.0) {
                return Ok(Keyring { header, key });
            }
        }
        Err(VaultError::IncorrectPasswordOrCorruptFile)
    }

    pub fn unlock_with_prf(header: KeyringHeader, credential_id: &str, prf_output: &[u8]) -> Result<Self> {
        let wrapping = hkdf_key(prf_output, b"prf");
        for slot in header
            .slots
            .iter()
            .filter(|s| s.kind == SlotKind::Prf && s.credential_id.as_deref() == Some(credential_id))
        {
            if let Ok(key) = Self::unwrap_slot(&header, slot, &wrapping) {
                return Ok(Keyring { header, key });
            }
        }
        Err(VaultError::IncorrectPasswordOrCorruptFile)
    }

    pub fn unlock_with_recovery_key(header: KeyringHeader, recovery_key: &str) -> Result<Self> {
        let wrapping = hkdf_key(normalize_recovery_key(recovery_key).as_bytes(), b"recovery");
        for slot in header.slots.iter().filter(|s| s.kind == SlotKind::Recovery) {
            if let Ok(key) = Self::unwrap_slot(&header, slot, &wrapping) {
                return Ok(Keyring { header, key });
            }
        }
        Err(VaultError::IncorrectPasswordOrCorruptFile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> KdfParams {
        KdfParams::fast_for_tests()
    }

    #[test]
    fn password_slot_round_trips() {
        let ring = Keyring::new_with_password("pw", fast()).unwrap();
        let again = Keyring::unlock_with_password(ring.header.clone(), "pw").unwrap();
        assert_eq!(ring.key(), again.key());
        assert!(Keyring::unlock_with_password(ring.header.clone(), "nope").is_err());
    }

    #[test]
    fn changing_the_password_keeps_the_same_vault_key() {
        let mut ring = Keyring::new_with_password("old", fast()).unwrap();
        let key = *ring.key();
        ring.change_password("new", fast()).unwrap();
        assert!(Keyring::unlock_with_password(ring.header.clone(), "old").is_err());
        assert_eq!(*Keyring::unlock_with_password(ring.header.clone(), "new").unwrap().key(), key);
        assert_eq!(ring.header.slots.len(), 1);
    }

    #[test]
    fn prf_slot_unlocks_only_with_the_same_output_and_credential() {
        let mut ring = Keyring::new_with_password("pw", fast()).unwrap();
        let prf = [42u8; 32];
        ring.add_prf_slot("cred-1", b"salt", &prf, "Phone").unwrap();
        assert_eq!(Keyring::unlock_with_prf(ring.header.clone(), "cred-1", &prf).unwrap().key(), ring.key());
        assert!(Keyring::unlock_with_prf(ring.header.clone(), "cred-1", &[43u8; 32]).is_err());
        assert!(Keyring::unlock_with_prf(ring.header.clone(), "cred-2", &prf).is_err());
    }

    #[test]
    fn recovery_key_ignores_formatting() {
        let mut ring = Keyring::new_with_password("pw", fast()).unwrap();
        let (_, rk) = ring.add_recovery_slot("Printed").unwrap();
        let sloppy = rk.to_lowercase().replace('-', " ");
        assert_eq!(Keyring::unlock_with_recovery_key(ring.header.clone(), &sloppy).unwrap().key(), ring.key());
    }

    #[test]
    fn a_slot_copied_into_another_vault_does_not_unlock_it() {
        let a = Keyring::new_with_password("pw", fast()).unwrap();
        let mut b = Keyring::new_with_password("other", fast()).unwrap();
        b.header.slots.push(a.header.slots[0].clone());
        // Same password, slot from vault A, but vault B's id is in the AAD.
        assert!(Keyring::unlock_with_password(b.header.clone(), "pw").is_err());
    }

    #[test]
    fn the_last_password_slot_cannot_be_removed() {
        let mut ring = Keyring::new_with_password("pw", fast()).unwrap();
        let id = ring.header.slots[0].id;
        assert!(matches!(ring.remove_slot(id), Err(VaultError::LastPasswordSlot)));
    }
}
