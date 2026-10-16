//! The vault file format, and the `Vault` type that owns records in
//! memory while unlocked.
//!
//! File layout (all integers little-endian):
//!
//! ```text
//! [4 bytes]  magic "CLV1"
//! [1 byte]   format version
//! [16 bytes] Argon2id salt
//! [4 bytes]  m_cost
//! [4 bytes]  t_cost
//! [4 bytes]  p_cost
//! [12 bytes] AES-GCM nonce
//! [...]      ciphertext (AES-256-GCM, tag appended by the cipher itself)
//! ```
//!
//! The plaintext the ciphertext decrypts to is JSON: a list of
//! [`crate::record::Record`]. JSON rather than a binary format for this
//! first version — it costs a few bytes, and it means the one thing this
//! crate's own tests can inspect by eye when something goes wrong is the
//! decrypted payload, not a hex dump.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{decrypt, encrypt, NONCE_LEN};
use crate::error::{Result, VaultError};
use crate::kdf::{derive_key, generate_salt, DerivedKey, KdfParams, SALT_LEN};
use crate::keypair::SHARED_KEY_LEN;
use crate::record::Record;

const MAGIC: &[u8; 4] = b"CLV1";
const FORMAT_VERSION: u8 = 1;
/// A shared (organization) vault: sealed with a pre-existing raw key
/// rather than one derived from a password, so there is no KDF salt or
/// parameters in this header — see [`Vault::seal_with_raw_key`].
const RAW_KEY_FORMAT_VERSION: u8 = 2;

/// A vault, unlocked and held in memory. Records are plain `Record`
/// values here — the whole point of "unlocked" is that they are usable —
/// which is exactly why nothing in this type persists to disk on its own;
/// [`Vault::seal`] is the only path back to an encrypted file, called
/// explicitly, never implicitly on drop (an implicit save-on-drop is how
/// a vault silently writes to a disk a caller did not ask it to touch).
#[derive(Debug, Clone)]
pub struct Vault {
    records: Vec<Record>,
}

impl Vault {
    /// A new, empty, unlocked vault — nothing is written to disk until
    /// [`Vault::seal`] is called explicitly.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn add_record(&mut self, record: Record) {
        self.records.push(record);
    }

    pub fn update_record(&mut self, id: Uuid, mut updated: Record) -> Result<()> {
        let existing = self
            .records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or(VaultError::RecordNotFound)?;
        updated.id = id;
        updated.created_at = existing.created_at;
        updated.updated_at = chrono::Utc::now();
        *existing = updated;
        Ok(())
    }

    pub fn delete_record(&mut self, id: Uuid) -> Result<()> {
        let before = self.records.len();
        self.records.retain(|r| r.id != id);
        if self.records.len() == before {
            return Err(VaultError::RecordNotFound);
        }
        Ok(())
    }

    pub fn get_record(&self, id: Uuid) -> Option<&Record> {
        self.records.iter().find(|r| r.id == id)
    }

    pub fn list_records(&self) -> &[Record] {
        &self.records
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Encrypt this vault's current contents into the on-disk file
    /// format, under a freshly generated salt and nonce. Called "seal"
    /// rather than "save" deliberately — this returns bytes, it does not
    /// write a file, so a caller decides where (and whether) those bytes
    /// land on disk.
    pub fn seal(&self, master_password: &str) -> Result<Vec<u8>> {
        self.seal_with_params(master_password, KdfParams::default())
    }

    /// Same as [`Vault::seal`], with explicit KDF parameters — the path a
    /// re-save of an existing vault takes, so re-sealing never silently
    /// upgrades (or downgrades) the parameters a vault was created with.
    pub fn seal_with_params(&self, master_password: &str, params: KdfParams) -> Result<Vec<u8>> {
        let salt = generate_salt();
        let key = derive_key(master_password, &salt, &params)?;
        let plaintext = serde_json::to_vec(&self.records)?;
        let (ciphertext, nonce) = encrypt(&key, &plaintext)?;

        let mut file = Vec::with_capacity(4 + 1 + SALT_LEN + 12 + NONCE_LEN + ciphertext.len());
        file.extend_from_slice(MAGIC);
        file.push(FORMAT_VERSION);
        file.extend_from_slice(&salt);
        file.extend_from_slice(&params.m_cost.to_le_bytes());
        file.extend_from_slice(&params.t_cost.to_le_bytes());
        file.extend_from_slice(&params.p_cost.to_le_bytes());
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&ciphertext);
        Ok(file)
    }

    /// Decrypt a vault file with the given master password. Returns
    /// exactly one error variant for every way this can fail due to a
    /// wrong password — [`VaultError::IncorrectPasswordOrCorruptFile`] —
    /// deliberately not distinguishing "wrong password" from "corrupt
    /// file" at this boundary, the same reasoning
    /// [`crate::crypto::decrypt`] already applies to a tampered
    /// ciphertext: an attacker (or a confused user) learns nothing more
    /// from the failure than "that did not work".
    pub fn unlock(file_bytes: &[u8], master_password: &str) -> Result<Self> {
        let header = ParsedHeader::parse(file_bytes)?;
        let key = derive_key(master_password, &header.salt, &header.params)
            .map_err(|_| VaultError::IncorrectPasswordOrCorruptFile)?;
        let plaintext = decrypt(&key, header.ciphertext, &header.nonce)
            .map_err(|_| VaultError::IncorrectPasswordOrCorruptFile)?;
        let records: Vec<Record> = serde_json::from_slice(&plaintext)
            .map_err(|_| VaultError::IncorrectPasswordOrCorruptFile)?;
        Ok(Self { records })
    }

    /// Seal with a pre-existing raw key instead of deriving one from a
    /// password — the path a shared (organization) vault takes. The key
    /// itself is generated once by [`crate::keypair::generate_shared_key`]
    /// and distributed by wrapping it per member device, never by giving
    /// every member the same password to remember.
    pub fn seal_with_raw_key(&self, key: &[u8; SHARED_KEY_LEN]) -> Result<Vec<u8>> {
        let derived = DerivedKey(*key);
        let plaintext = serde_json::to_vec(&self.records)?;
        let (ciphertext, nonce) = encrypt(&derived, &plaintext)?;

        let mut file = Vec::with_capacity(4 + 1 + NONCE_LEN + ciphertext.len());
        file.extend_from_slice(MAGIC);
        file.push(RAW_KEY_FORMAT_VERSION);
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&ciphertext);
        Ok(file)
    }

    /// Open a shared vault file with its raw key (recovered by unwrapping
    /// a [`crate::keypair::DeviceKeypair`]'s own copy). Refuses a file
    /// sealed under a master password just as firmly as the reverse —
    /// [`Vault::unlock`] and this are not interchangeable, because mixing
    /// them up would mean treating a KDF salt as ciphertext or vice versa.
    pub fn unlock_with_raw_key(file_bytes: &[u8], key: &[u8; SHARED_KEY_LEN]) -> Result<Self> {
        if file_bytes.len() < 5 {
            return Err(VaultError::TruncatedFile);
        }
        if &file_bytes[0..4] != MAGIC {
            return Err(VaultError::NotAClaviumVault);
        }
        let version = file_bytes[4];
        if version != RAW_KEY_FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }

        let header_len = 4 + 1 + NONCE_LEN;
        if file_bytes.len() < header_len {
            return Err(VaultError::TruncatedFile);
        }

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&file_bytes[5..5 + NONCE_LEN]);
        let ciphertext = &file_bytes[5 + NONCE_LEN..];

        let derived = DerivedKey(*key);
        let plaintext = decrypt(&derived, ciphertext, &nonce)
            .map_err(|_| VaultError::IncorrectPasswordOrCorruptFile)?;
        let records: Vec<Record> = serde_json::from_slice(&plaintext)
            .map_err(|_| VaultError::IncorrectPasswordOrCorruptFile)?;
        Ok(Self { records })
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

/// The parsed, not-yet-decrypted header of a vault file — split out so
/// `unlock` reads cleanly as "parse the header, then try to decrypt",
/// rather than one function doing both.
struct ParsedHeader<'a> {
    salt: [u8; SALT_LEN],
    params: KdfParams,
    nonce: [u8; NONCE_LEN],
    ciphertext: &'a [u8],
}

impl<'a> ParsedHeader<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        // Magic and version are checked before the full header length —
        // a shorter file in a *different*, valid format (the raw-key
        // shared-vault format is shorter, having no salt or KDF
        // parameters) must report "wrong version", not "truncated", or a
        // shared vault opened with the wrong function gets a misleading
        // error pointing someone at file corruption that never happened.
        if bytes.len() < 5 {
            return Err(VaultError::TruncatedFile);
        }
        if &bytes[0..4] != MAGIC {
            return Err(VaultError::NotAClaviumVault);
        }
        let version = bytes[4];
        if version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }

        let header_len = 4 + 1 + SALT_LEN + 4 + 4 + 4 + NONCE_LEN;
        if bytes.len() < header_len {
            return Err(VaultError::TruncatedFile);
        }

        let mut offset = 5;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[offset..offset + SALT_LEN]);
        offset += SALT_LEN;

        let m_cost = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let t_cost = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let p_cost = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[offset..offset + NONCE_LEN]);
        offset += NONCE_LEN;

        let ciphertext = &bytes[offset..];

        Ok(Self {
            salt,
            params: KdfParams {
                m_cost,
                t_cost,
                p_cost,
            },
            nonce,
            ciphertext,
        })
    }
}

/// Serializable view of a vault's data without a master password attached
/// — not part of the file format, just a convenience for a caller that
/// wants a snapshot of what `list_records` would return, shaped for
/// logging or a non-cryptographic test assertion.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultSnapshot {
    pub records: Vec<Record>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_vault_unlocks_with_the_correct_password() {
        let mut vault = Vault::new();
        vault.add_record(Record::new("Email"));

        let sealed = vault.seal("correct horse battery staple").unwrap();
        let unlocked = Vault::unlock(&sealed, "correct horse battery staple").unwrap();

        assert_eq!(unlocked.record_count(), 1);
        assert_eq!(unlocked.list_records()[0].title, "Email");
    }

    #[test]
    fn the_wrong_password_refuses_to_unlock() {
        let vault = Vault::new();
        let sealed = vault.seal("correct horse battery staple").unwrap();
        let result = Vault::unlock(&sealed, "wrong password");
        assert!(matches!(
            result,
            Err(VaultError::IncorrectPasswordOrCorruptFile)
        ));
    }

    #[test]
    fn every_record_round_trips_exactly() {
        let mut vault = Vault::new();
        let mut record = Record::new("Bank");
        record.username = "enrico".to_string();
        record.password = "s3cr3t!".to_string();
        record.url = "https://bank.example".to_string();
        record.notes = "call before large transfers".to_string();
        vault.add_record(record.clone());

        let sealed = vault.seal("pw").unwrap();
        let unlocked = Vault::unlock(&sealed, "pw").unwrap();

        assert_eq!(unlocked.get_record(record.id).unwrap(), &record);
    }

    #[test]
    fn a_too_short_blob_with_no_magic_is_refused_not_panicked_on() {
        // Not even long enough to check for a magic header — must not
        // panic on an out-of-bounds slice.
        let result = Vault::unlock(b"hi", "any password");
        assert!(matches!(result, Err(VaultError::TruncatedFile)));
    }

    #[test]
    fn a_file_with_real_magic_and_version_but_cut_short_is_refused_as_truncated() {
        // Real magic, real version 1 — but cut off before the salt/KDF/
        // nonce header is complete, which is a different failure from
        // "not a Clavium vault at all" and must be reported as such.
        let mut fake = MAGIC.to_vec();
        fake.push(FORMAT_VERSION);
        fake.extend_from_slice(&[0u8; 3]); // nowhere near a full header
        let result = Vault::unlock(&fake, "any password");
        assert!(matches!(result, Err(VaultError::TruncatedFile)));
    }

    #[test]
    fn a_file_with_the_wrong_magic_bytes_is_refused() {
        let mut fake = vec![0u8; 100];
        fake[0..4].copy_from_slice(b"NOPE");
        let result = Vault::unlock(&fake, "any password");
        assert!(matches!(result, Err(VaultError::NotAClaviumVault)));
    }

    #[test]
    fn updating_a_record_preserves_its_id_and_created_at() {
        let mut vault = Vault::new();
        let record = Record::new("Original");
        let id = record.id;
        let created_at = record.created_at;
        vault.add_record(record);

        let mut replacement = Record::new("Renamed");
        replacement.username = "new-user".to_string();
        vault.update_record(id, replacement).unwrap();

        let updated = vault.get_record(id).unwrap();
        assert_eq!(updated.id, id);
        assert_eq!(updated.created_at, created_at);
        assert_eq!(updated.title, "Renamed");
    }

    #[test]
    fn updating_a_record_that_does_not_exist_is_refused() {
        let mut vault = Vault::new();
        let result = vault.update_record(Uuid::new_v4(), Record::new("X"));
        assert!(matches!(result, Err(VaultError::RecordNotFound)));
    }

    #[test]
    fn deleting_a_record_removes_it() {
        let mut vault = Vault::new();
        let record = Record::new("To delete");
        let id = record.id;
        vault.add_record(record);
        vault.add_record(Record::new("Stays"));

        vault.delete_record(id).unwrap();

        assert_eq!(vault.record_count(), 1);
        assert!(vault.get_record(id).is_none());
    }

    #[test]
    fn deleting_a_record_that_does_not_exist_is_refused() {
        let mut vault = Vault::new();
        let result = vault.delete_record(Uuid::new_v4());
        assert!(matches!(result, Err(VaultError::RecordNotFound)));
    }

    #[test]
    fn an_empty_vault_seals_and_unlocks_cleanly() {
        let vault = Vault::new();
        let sealed = vault.seal("pw").unwrap();
        let unlocked = Vault::unlock(&sealed, "pw").unwrap();
        assert_eq!(unlocked.record_count(), 0);
    }

    #[test]
    fn two_seals_of_the_same_vault_produce_different_bytes() {
        // A fresh salt and nonce every time, even for identical content —
        // the file itself must never become a fingerprint of unchanged data.
        let mut vault = Vault::new();
        vault.add_record(Record::new("Same content"));
        let first = vault.seal("pw").unwrap();
        let second = vault.seal("pw").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn a_shared_vault_sealed_with_a_raw_key_unlocks_with_the_same_key() {
        let mut vault = Vault::new();
        vault.add_record(Record::new("Shared login"));
        let key = crate::keypair::generate_shared_key();

        let sealed = vault.seal_with_raw_key(&key).unwrap();
        let unlocked = Vault::unlock_with_raw_key(&sealed, &key).unwrap();

        assert_eq!(unlocked.record_count(), 1);
        assert_eq!(unlocked.list_records()[0].title, "Shared login");
    }

    #[test]
    fn a_shared_vault_refuses_the_wrong_raw_key() {
        let vault = Vault::new();
        let key = crate::keypair::generate_shared_key();
        let wrong_key = crate::keypair::generate_shared_key();
        let sealed = vault.seal_with_raw_key(&key).unwrap();

        assert!(Vault::unlock_with_raw_key(&sealed, &wrong_key).is_err());
    }

    #[test]
    fn a_password_sealed_vault_cannot_be_opened_as_a_shared_vault_or_vice_versa() {
        let vault = Vault::new();
        let password_sealed = vault.seal("a password").unwrap();
        let key = crate::keypair::generate_shared_key();
        let raw_key_sealed = vault.seal_with_raw_key(&key).unwrap();

        assert!(matches!(
            Vault::unlock_with_raw_key(&password_sealed, &key),
            Err(VaultError::UnsupportedVersion(1))
        ));
        assert!(matches!(
            Vault::unlock(&raw_key_sealed, "a password"),
            Err(VaultError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn tampering_with_a_sealed_file_prevents_unlock_even_with_the_right_password() {
        let mut vault = Vault::new();
        vault.add_record(Record::new("Sensitive"));
        let mut sealed = vault.seal("pw").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        let result = Vault::unlock(&sealed, "pw");
        assert!(result.is_err());
    }
}
