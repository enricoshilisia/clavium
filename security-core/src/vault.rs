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

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::categorize;
use crate::crypto::{decrypt, decrypt_with_aad, encrypt, encrypt_with_aad, NONCE_LEN};
use crate::keyring::{Keyring, KeyringHeader};
use crate::record::CategorySource;
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
/// A personal vault under a random vault key wrapped by key slots:
///
/// ```text
/// [4 bytes]  magic "CLV1"
/// [1 byte]   3
/// [4 bytes]  header length N (u32 LE)
/// [N bytes]  keyring header JSON (vault id + key slots, no secrets)
/// [12 bytes] AES-GCM nonce
/// [...]      ciphertext of the payload JSON; AAD = every byte above the nonce
/// ```
const KEYRING_FORMAT_VERSION: u8 = 3;
const MAX_HEADER_LEN: usize = 1 << 20;

struct V3Body<'a> {
    aad: &'a [u8],
    nonce: [u8; NONCE_LEN],
    ciphertext: &'a [u8],
}

fn parse_v3(bytes: &[u8]) -> Result<(KeyringHeader, V3Body<'_>)> {
    if bytes.len() < 5 {
        return Err(VaultError::TruncatedFile);
    }
    if &bytes[0..4] != MAGIC {
        return Err(VaultError::NotAClaviumVault);
    }
    if bytes[4] != KEYRING_FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion(bytes[4]));
    }
    if bytes.len() < 9 {
        return Err(VaultError::TruncatedFile);
    }
    let header_len = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as usize;
    if header_len > MAX_HEADER_LEN || bytes.len() < 9 + header_len + NONCE_LEN {
        return Err(VaultError::TruncatedFile);
    }
    let header: KeyringHeader = serde_json::from_slice(&bytes[9..9 + header_len])
        .map_err(|_| VaultError::IncorrectPasswordOrCorruptFile)?;
    let aad = &bytes[..9 + header_len];
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[9 + header_len..9 + header_len + NONCE_LEN]);
    let ciphertext = &bytes[9 + header_len + NONCE_LEN..];
    Ok((header, V3Body { aad, nonce, ciphertext }))
}

/// A vault, unlocked and held in memory. Records are plain `Record`
/// values here — the whole point of "unlocked" is that they are usable —
/// which is exactly why nothing in this type persists to disk on its own;
/// [`Vault::seal`] is the only path back to an encrypted file, called
/// explicitly, never implicitly on drop (an implicit save-on-drop is how
/// a vault silently writes to a disk a caller did not ask it to touch).
#[derive(Debug, Clone)]
pub struct Vault {
    /// Live records and, for records already synced, tombstones of deleted
    /// ones. Public accessors hide tombstones.
    pub(crate) records: Vec<Record>,
    /// host -> category rules a person taught the vault by recategorising.
    pub(crate) learned_categories: BTreeMap<String, String>,
    /// Folder names, so an empty folder survives.
    pub(crate) folders: Vec<String>,
    /// Highest server revision this vault has pulled.
    pub(crate) sync_cursor: u64,
    /// Present for v3 vaults (and v1 vaults opened with [`Vault::open`],
    /// which upgrade on their next [`Vault::save`]).
    pub(crate) keyring: Option<Keyring>,
    /// Team vaults: account id -> public key first seen for it (trust on
    /// first use, see `team.rs`). Personal vaults only.
    pub(crate) known_keys: BTreeMap<String, String>,
}

/// The encrypted body of a v3 vault file.
#[derive(Serialize, Deserialize, Default)]
struct VaultPayload {
    records: Vec<Record>,
    #[serde(default)]
    learned_categories: BTreeMap<String, String>,
    #[serde(default)]
    folders: Vec<String>,
    #[serde(default)]
    sync_cursor: u64,
    #[serde(default)]
    known_keys: BTreeMap<String, String>,
}

impl Vault {
    /// A new, empty, unlocked vault with no key yet. Use
    /// [`Vault::create`] for a vault that can be [`Vault::save`]d.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            learned_categories: BTreeMap::new(),
            folders: Vec::new(),
            sync_cursor: 0,
            keyring: None,
            known_keys: BTreeMap::new(),
        }
    }

    fn from_records(records: Vec<Record>) -> Self {
        let mut v = Self::new();
        v.records = records;
        v
    }

    /// Add a record, auto-categorising it unless a person already chose a
    /// category. Marked dirty so the next sync pushes it.
    pub fn add_record(&mut self, mut record: Record) {
        categorize::auto_categorize(&mut record, &self.learned_categories);
        record.dirty = true;
        record.deleted_at = None;
        self.records.push(record);
    }

    /// Replace a record's content. Identity, creation time and sync
    /// revision are kept from the stored record whatever `updated` says.
    pub fn update_record(&mut self, id: Uuid, mut updated: Record) -> Result<()> {
        let learned = self.learned_categories.clone();
        let existing = self
            .records
            .iter_mut()
            .find(|r| r.id == id && !r.is_deleted())
            .ok_or(VaultError::RecordNotFound)?;
        updated.id = id;
        updated.created_at = existing.created_at;
        updated.updated_at = chrono::Utc::now();
        updated.revision = existing.revision;
        updated.dirty = true;
        updated.deleted_at = None;
        categorize::auto_categorize(&mut updated, &learned);
        *existing = updated;
        Ok(())
    }

    /// Delete a record. A record the server has seen becomes a tombstone
    /// so the deletion syncs; one that never left this device just goes.
    pub fn delete_record(&mut self, id: Uuid) -> Result<()> {
        let idx = self
            .records
            .iter()
            .position(|r| r.id == id && !r.is_deleted())
            .ok_or(VaultError::RecordNotFound)?;
        if self.records[idx].revision == 0 {
            self.records.remove(idx);
        } else {
            self.records[idx].tombstone();
        }
        Ok(())
    }

    pub fn get_record(&self, id: Uuid) -> Option<&Record> {
        self.records.iter().find(|r| r.id == id && !r.is_deleted())
    }

    /// Live records (tombstones excluded), cloned.
    pub fn list_records(&self) -> Vec<Record> {
        self.records.iter().filter(|r| !r.is_deleted()).cloned().collect()
    }

    pub fn record_count(&self) -> usize {
        self.records.iter().filter(|r| !r.is_deleted()).count()
    }

    // ---- categories, folders, tags ----

    /// A person picks a category by hand. With `learn`, every other
    /// auto-categorised record on the same site follows, and future ones do
    /// too. `None` hands the record back to the auto-categoriser.
    pub fn set_category(&mut self, id: Uuid, category: Option<String>, learn: bool) -> Result<()> {
        if let Some(c) = &category {
            if !categorize::is_known_category(c) {
                return Err(VaultError::UnknownCategory(c.clone()));
            }
        }
        let record = self
            .records
            .iter_mut()
            .find(|r| r.id == id && !r.is_deleted())
            .ok_or(VaultError::RecordNotFound)?;
        let host = categorize::host_of(&record.url);
        match category {
            Some(c) => {
                record.category = Some(c.clone());
                record.category_source = CategorySource::User;
                if learn {
                    if let Some(h) = host {
                        self.learned_categories.insert(h, c);
                    }
                }
            }
            None => {
                record.category_source = CategorySource::Auto;
                if let Some(h) = host {
                    self.learned_categories.remove(&h);
                }
            }
        }
        record.updated_at = chrono::Utc::now();
        record.dirty = true;
        self.recategorize_all();
        Ok(())
    }

    /// Re-run auto-categorisation over every record. Returns how many
    /// changed (those are marked dirty).
    pub fn recategorize_all(&mut self) -> usize {
        let learned = self.learned_categories.clone();
        let mut changed = 0;
        for r in self.records.iter_mut().filter(|r| !r.is_deleted()) {
            if categorize::auto_categorize(r, &learned) {
                r.dirty = true;
                changed += 1;
            }
        }
        changed
    }

    pub fn learned_categories(&self) -> &BTreeMap<String, String> {
        &self.learned_categories
    }

    /// Record counts per category slug (`"uncategorized"` for none).
    pub fn category_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for r in self.records.iter().filter(|r| !r.is_deleted()) {
            let key = r.category.clone().unwrap_or_else(|| "uncategorized".into());
            *counts.entry(key).or_insert(0) += 1;
        }
        counts
    }

    /// Every folder name in use or explicitly created, sorted.
    pub fn folders(&self) -> Vec<String> {
        let mut all: Vec<String> = self.folders.clone();
        for r in self.records.iter().filter(|r| !r.is_deleted()) {
            if let Some(f) = &r.folder {
                all.push(f.clone());
            }
        }
        all.sort();
        all.dedup();
        all
    }

    pub fn create_folder(&mut self, name: &str) {
        let name = name.trim();
        if !name.is_empty() && !self.folders.iter().any(|f| f == name) {
            self.folders.push(name.to_string());
        }
    }

    /// Every tag in use, sorted.
    pub fn tags(&self) -> Vec<String> {
        let mut all: Vec<String> = self
            .records
            .iter()
            .filter(|r| !r.is_deleted())
            .flat_map(|r| r.tags.iter().cloned())
            .collect();
        all.sort();
        all.dedup();
        all
    }

    /// Case-insensitive search over title, username, url, notes, tags and
    /// folder. An empty query returns everything.
    pub fn search(&self, query: &str) -> Vec<Record> {
        let q = query.trim().to_lowercase();
        self.records
            .iter()
            .filter(|r| !r.is_deleted())
            .filter(|r| {
                q.is_empty()
                    || r.title.to_lowercase().contains(&q)
                    || r.username.to_lowercase().contains(&q)
                    || r.url.to_lowercase().contains(&q)
                    || r.notes.to_lowercase().contains(&q)
                    || r.folder.as_deref().map_or(false, |f| f.to_lowercase().contains(&q))
                    || r.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .cloned()
            .collect()
    }

    // ---- v3: keyring-protected vault ----

    /// A new, empty vault protected by `master_password`.
    pub fn create(master_password: &str) -> Result<Self> {
        Self::create_with_params(master_password, KdfParams::default())
    }

    pub fn create_with_params(master_password: &str, params: KdfParams) -> Result<Self> {
        let mut v = Self::new();
        v.keyring = Some(Keyring::new_with_password(master_password, params)?);
        Ok(v)
    }

    /// Open any personal vault file (v1 or v3) with its master password.
    /// A v1 file gets a fresh keyring here, so it is upgraded to v3 the
    /// next time it is saved.
    pub fn open(file_bytes: &[u8], master_password: &str) -> Result<Self> {
        let version = Self::file_version(file_bytes)?;
        match version {
            FORMAT_VERSION => {
                let params = ParsedHeader::parse(file_bytes)?.params;
                let mut v = Self::unlock(file_bytes, master_password)?;
                v.keyring = Some(Keyring::new_with_password(master_password, params)?);
                // Every record is new to sync.
                for r in &mut v.records {
                    r.dirty = true;
                }
                Ok(v)
            }
            KEYRING_FORMAT_VERSION => {
                let (header, _) = parse_v3(file_bytes)?;
                let ring = Keyring::unlock_with_password(header, master_password)?;
                Self::decrypt_v3(file_bytes, ring)
            }
            other => Err(VaultError::UnsupportedVersion(other)),
        }
    }

    /// Open a v3 vault with a passkey's PRF output instead of the password.
    pub fn open_with_prf(file_bytes: &[u8], credential_id: &str, prf_output: &[u8]) -> Result<Self> {
        let (header, _) = parse_v3(file_bytes)?;
        let ring = Keyring::unlock_with_prf(header, credential_id, prf_output)?;
        Self::decrypt_v3(file_bytes, ring)
    }

    /// Open a v3 vault with a recovery key.
    pub fn open_with_recovery_key(file_bytes: &[u8], recovery_key: &str) -> Result<Self> {
        let (header, _) = parse_v3(file_bytes)?;
        let ring = Keyring::unlock_with_recovery_key(header, recovery_key)?;
        Self::decrypt_v3(file_bytes, ring)
    }

    /// The keyring header of a v3 file, readable without any secret: a
    /// client uses it to see which passkeys can unlock this vault.
    pub fn read_header(file_bytes: &[u8]) -> Result<KeyringHeader> {
        Ok(parse_v3(file_bytes)?.0)
    }

    /// An empty vault around an already-unlocked keyring: how a new device
    /// starts after unlocking the keyring it downloaded from the server.
    pub fn from_keyring(keyring: Keyring) -> Self {
        let mut v = Self::new();
        v.keyring = Some(keyring);
        v
    }

    fn file_version(bytes: &[u8]) -> Result<u8> {
        if bytes.len() < 5 {
            return Err(VaultError::TruncatedFile);
        }
        if &bytes[0..4] != MAGIC {
            return Err(VaultError::NotAClaviumVault);
        }
        Ok(bytes[4])
    }

    /// Open a v3 file with an already-unlocked keyring (team vault caches).
    pub(crate) fn open_with_keyring(file_bytes: &[u8], ring: Keyring) -> Result<Self> {
        Self::decrypt_v3(file_bytes, ring)
    }

    fn decrypt_v3(file_bytes: &[u8], ring: Keyring) -> Result<Self> {
        let (_, body) = parse_v3(file_bytes)?;
        let plaintext = Zeroizing::new(
            decrypt_with_aad(ring.key(), body.ciphertext, &body.nonce, body.aad)
                .map_err(|_| VaultError::IncorrectPasswordOrCorruptFile)?,
        );
        let payload: VaultPayload = serde_json::from_slice(&plaintext)
            .map_err(|_| VaultError::IncorrectPasswordOrCorruptFile)?;
        Ok(Self {
            records: payload.records,
            learned_categories: payload.learned_categories,
            folders: payload.folders,
            sync_cursor: payload.sync_cursor,
            keyring: Some(ring),
            known_keys: payload.known_keys,
        })
    }

    /// Encrypt this vault into a v3 file under its own vault key. No KDF
    /// runs here, so saving is fast and needs no password in memory.
    pub fn save(&self) -> Result<Vec<u8>> {
        let ring = self.keyring.as_ref().ok_or(VaultError::NoKeyring)?;
        let header = serde_json::to_vec(&ring.header)?;
        let mut file = Vec::with_capacity(9 + header.len() + NONCE_LEN + 64);
        file.extend_from_slice(MAGIC);
        file.push(KEYRING_FORMAT_VERSION);
        file.extend_from_slice(&(header.len() as u32).to_le_bytes());
        file.extend_from_slice(&header);
        let aad = file.clone();
        let payload = Zeroizing::new(serde_json::to_vec(&VaultPayload {
            records: self.records.clone(),
            learned_categories: self.learned_categories.clone(),
            folders: self.folders.clone(),
            sync_cursor: self.sync_cursor,
            known_keys: self.known_keys.clone(),
        })?);
        let (ciphertext, nonce) = encrypt_with_aad(ring.key(), &payload, &aad)?;
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&ciphertext);
        Ok(file)
    }

    pub fn keyring(&self) -> Option<&Keyring> {
        self.keyring.as_ref()
    }

    fn keyring_mut(&mut self) -> Result<&mut Keyring> {
        self.keyring.as_mut().ok_or(VaultError::NoKeyring)
    }

    pub fn change_master_password(&mut self, new_password: &str) -> Result<()> {
        self.keyring_mut()?.change_password(new_password, KdfParams::default())
    }

    pub fn change_master_password_with_params(&mut self, new_password: &str, params: KdfParams) -> Result<()> {
        self.keyring_mut()?.change_password(new_password, params)
    }

    pub fn add_prf_slot(&mut self, credential_id: &str, prf_salt: &[u8], prf_output: &[u8], label: &str) -> Result<Uuid> {
        self.keyring_mut()?.add_prf_slot(credential_id, prf_salt, prf_output, label)
    }

    pub fn add_recovery_slot(&mut self, label: &str) -> Result<(Uuid, Zeroizing<String>)> {
        self.keyring_mut()?.add_recovery_slot(label)
    }

    pub fn remove_slot(&mut self, slot_id: Uuid) -> Result<()> {
        self.keyring_mut()?.remove_slot(slot_id)
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
        Ok(Self::from_records(records))
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
        Ok(Self::from_records(records))
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
        // add_record auto-categorises, so compare against what was stored.
        let stored = vault.get_record(record.id).unwrap().clone();
        assert_eq!(stored.category.as_deref(), Some("banking"));

        let sealed = vault.seal("pw").unwrap();
        let unlocked = Vault::unlock(&sealed, "pw").unwrap();

        assert_eq!(unlocked.get_record(record.id).unwrap(), &stored);
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

    // ---- v3 ----

    fn fast() -> KdfParams {
        KdfParams::fast_for_tests()
    }

    #[test]
    fn a_v3_vault_saves_and_opens() {
        let mut v = Vault::create_with_params("pw", fast()).unwrap();
        let mut r = Record::new("KCB");
        r.url = "https://ke.kcbgroup.com".into();
        v.add_record(r.clone());
        let bytes = v.save().unwrap();
        assert_eq!(bytes[4], KEYRING_FORMAT_VERSION);
        let opened = Vault::open(&bytes, "pw").unwrap();
        let got = opened.get_record(r.id).unwrap();
        assert_eq!(got.title, "KCB");
        assert_eq!(got.category.as_deref(), Some("banking"), "auto-categorised on add");
        assert!(matches!(Vault::open(&bytes, "wrong"), Err(VaultError::IncorrectPasswordOrCorruptFile)));
    }

    #[test]
    fn a_v1_vault_opens_and_upgrades_to_v3_on_save() {
        let mut old = Vault::new();
        old.add_record(Record::new("Legacy"));
        let v1 = old.seal_with_params("pw", fast()).unwrap();
        let opened = Vault::open(&v1, "pw").unwrap();
        let v3 = opened.save().unwrap();
        assert_eq!(v3[4], KEYRING_FORMAT_VERSION);
        let again = Vault::open(&v3, "pw").unwrap();
        assert_eq!(again.list_records()[0].title, "Legacy");
    }

    #[test]
    fn changing_the_master_password_does_not_reencrypt_records_differently() {
        let mut v = Vault::create_with_params("old", fast()).unwrap();
        v.add_record(Record::new("A"));
        v.change_master_password_with_params("new", fast()).unwrap();
        let bytes = v.save().unwrap();
        assert!(Vault::open(&bytes, "old").is_err());
        assert_eq!(Vault::open(&bytes, "new").unwrap().record_count(), 1);
    }

    #[test]
    fn passkey_and_recovery_slots_open_the_vault() {
        let mut v = Vault::create_with_params("pw", fast()).unwrap();
        v.add_record(Record::new("A"));
        v.add_prf_slot("cred", b"salt", &[9u8; 32], "Laptop passkey").unwrap();
        let (_, rk) = v.add_recovery_slot("Paper").unwrap();
        let bytes = v.save().unwrap();
        assert_eq!(Vault::open_with_prf(&bytes, "cred", &[9u8; 32]).unwrap().record_count(), 1);
        assert_eq!(Vault::open_with_recovery_key(&bytes, &rk).unwrap().record_count(), 1);
        let header = Vault::read_header(&bytes).unwrap();
        assert_eq!(header.slots.len(), 3);
    }

    #[test]
    fn stripping_a_key_slot_from_the_header_breaks_the_payload() {
        let mut v = Vault::create_with_params("pw", fast()).unwrap();
        v.add_recovery_slot("Paper").unwrap();
        let bytes = v.save().unwrap();
        // Rebuild the file with the recovery slot removed but the same body.
        let (mut header, body) = parse_v3(&bytes).unwrap();
        header.slots.retain(|s| s.kind == crate::keyring::SlotKind::Password);
        let hjson = serde_json::to_vec(&header).unwrap();
        let mut forged = MAGIC.to_vec();
        forged.push(KEYRING_FORMAT_VERSION);
        forged.extend_from_slice(&(hjson.len() as u32).to_le_bytes());
        forged.extend_from_slice(&hjson);
        forged.extend_from_slice(&body.nonce);
        forged.extend_from_slice(body.ciphertext);
        assert!(Vault::open(&forged, "pw").is_err());
    }

    #[test]
    fn a_user_category_with_learn_applies_to_the_same_site() {
        let mut v = Vault::create_with_params("pw", fast()).unwrap();
        let mut a = Record::new("GitHub personal");
        a.url = "https://github.com".into();
        let mut b = Record::new("GitHub work");
        b.url = "https://github.com/orgs/acme".into();
        let (ida, idb) = (a.id, b.id);
        v.add_record(a);
        v.add_record(b);
        assert_eq!(v.get_record(idb).unwrap().category.as_deref(), Some("development"));
        v.set_category(ida, Some("work".into()), true).unwrap();
        assert_eq!(v.get_record(idb).unwrap().category.as_deref(), Some("work"));
        let reopened = Vault::open(&v.save().unwrap(), "pw").unwrap();
        assert_eq!(reopened.learned_categories().get("github.com").map(String::as_str), Some("work"));
        assert!(v.set_category(ida, Some("nonsense".into()), false).is_err());
    }

    #[test]
    fn search_and_folders_and_tags() {
        let mut v = Vault::new();
        let mut r = Record::new("Office Wi-Fi");
        r.folder = Some("Work".into());
        r.tags = vec!["office".into(), "network".into()];
        v.add_record(r);
        v.create_folder("Empty folder");
        assert_eq!(v.search("wi-fi").len(), 1);
        assert_eq!(v.search("OFFICE").len(), 1);
        assert_eq!(v.search("nothing").len(), 0);
        assert_eq!(v.folders(), vec!["Empty folder".to_string(), "Work".to_string()]);
        assert_eq!(v.tags(), vec!["network".to_string(), "office".to_string()]);
        assert_eq!(v.category_counts().get("network"), Some(&1));
    }
}
