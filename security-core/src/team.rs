//! Team vaults: vaults shared by several people, readable by nobody else,
//! including the server.
//!
//! Keys
//! - Every account has one X25519 key pair. The public half is on the
//!   server. The private half is encrypted with that person's personal
//!   vault key (which all their devices already share through the
//!   keyring), so a new phone gets team access as soon as it unlocks the
//!   personal vault, with no one else online.
//! - Every team vault has a random 32-byte key. Each member gets their own
//!   copy, sealed to their account public key (X25519 + HKDF-SHA256 +
//!   AES-256-GCM, a fresh ephemeral key per copy). The server stores these
//!   copies and can open none of them.
//! - Content syncs per item exactly like a personal vault (see `sync.rs`),
//!   encrypted under the team key with the team vault id in the AAD.
//!
//! Trust: the server hands out members' public keys. To stop a server
//! from quietly swapping in its own key, a client remembers the key it
//! first saw for each account ([`Vault::check_known_key`]) and refuses to
//! share with a changed key until a person confirms the new fingerprint.

use base64::engine::general_purpose::STANDARD as B64;
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
use crate::keyring::{Keyring, KeyringHeader, VAULT_KEY_LEN};
use crate::vault::Vault;

pub type TeamKey = Zeroizing<[u8; VAULT_KEY_LEN]>;

/// One account's key pair, unlocked. Never serialized in the clear.
pub struct AccountKeys {
    secret: StaticSecret,
    pub public_key: [u8; 32],
}

/// The account key as the server stores it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAccountKey {
    /// base64 X25519 public key.
    pub public_key: String,
    /// base64 nonce || ciphertext of the private key under the personal
    /// vault key.
    pub encrypted_private_key: String,
}

/// A team key sealed for one member.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappedTeamKey {
    /// base64 ephemeral X25519 public key.
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

fn b64_32(s: &str) -> Result<[u8; 32]> {
    let v = B64.decode(s.trim()).map_err(|_| VaultError::TeamKeyInvalid)?;
    v.try_into().map_err(|_| VaultError::TeamKeyInvalid)
}

fn private_aad(vault_id: Uuid, public_key: &[u8; 32]) -> Vec<u8> {
    let mut a = b"clavium-account-key-v1|".to_vec();
    a.extend_from_slice(vault_id.as_bytes());
    a.extend_from_slice(public_key);
    a
}

fn wrap_context(team_id: Uuid, account_id: &str, key_version: u32, recipient: &[u8; 32], ephemeral: &[u8; 32]) -> Vec<u8> {
    let mut info = b"clavium-team-key-v1|".to_vec();
    info.extend_from_slice(team_id.as_bytes());
    info.extend_from_slice(account_id.as_bytes());
    info.push(b'|');
    info.extend_from_slice(&key_version.to_be_bytes());
    info.extend_from_slice(recipient);
    info.extend_from_slice(ephemeral);
    info
}

fn derive(shared: &[u8; 32], context: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(b"clavium-team"), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(context, key.as_mut()).expect("valid HKDF length");
    key
}

/// Short, human-comparable fingerprint of a public key, e.g.
/// `4F2A 91C0 7B3E 55D8`. Two people reading the same fingerprint on two
/// screens know the server did not swap the key.
pub fn fingerprint(public_key_b64: &str) -> Result<String> {
    let pk = b64_32(public_key_b64)?;
    let digest = Sha256::digest([b"clavium-fp-v1|".as_slice(), &pk].concat());
    let hex: String = digest[..8].iter().map(|b| format!("{b:02X}")).collect();
    Ok(hex.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(" "))
}

impl AccountKeys {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret).to_bytes();
        Self { secret, public_key }
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.public_key)
    }

    /// Encrypt the private key with the personal vault's key, for the server.
    pub fn store(&self, personal: &Keyring) -> Result<StoredAccountKey> {
        let secret = Zeroizing::new(self.secret.to_bytes());
        let (ct, nonce) = encrypt_with_aad(personal.key(), secret.as_ref(), &private_aad(personal.vault_id(), &self.public_key))?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ct);
        Ok(StoredAccountKey { public_key: self.public_key_b64(), encrypted_private_key: B64.encode(blob) })
    }

    /// Decrypt a stored account key with the personal vault's key. Fails if
    /// it was made under another personal vault (for example after a sync
    /// reset), in which case the caller makes a new key pair.
    pub fn load(stored: &StoredAccountKey, personal: &Keyring) -> Result<Self> {
        let public_key = b64_32(&stored.public_key)?;
        let blob = B64.decode(&stored.encrypted_private_key).map_err(|_| VaultError::TeamKeyInvalid)?;
        if blob.len() <= NONCE_LEN {
            return Err(VaultError::TeamKeyInvalid);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&blob[..NONCE_LEN]);
        let plain = Zeroizing::new(
            decrypt_with_aad(personal.key(), &blob[NONCE_LEN..], &nonce, &private_aad(personal.vault_id(), &public_key))
                .map_err(|_| VaultError::TeamKeyInvalid)?,
        );
        let bytes: [u8; 32] = plain.as_slice().try_into().map_err(|_| VaultError::TeamKeyInvalid)?;
        let secret = StaticSecret::from(bytes);
        if PublicKey::from(&secret).to_bytes() != public_key {
            return Err(VaultError::TeamKeyInvalid);
        }
        Ok(Self { secret, public_key })
    }

    /// Open this account's copy of a team key.
    pub fn unwrap_team_key(&self, wrapped: &WrappedTeamKey, team_id: Uuid, account_id: &str, key_version: u32) -> Result<TeamKey> {
        let eph = b64_32(&wrapped.ephemeral_public_key)?;
        let shared = Zeroizing::new(self.secret.diffie_hellman(&PublicKey::from(eph)).to_bytes());
        let ctx = wrap_context(team_id, account_id, key_version, &self.public_key, &eph);
        let key = derive(&shared, &ctx);
        let nonce: [u8; NONCE_LEN] = B64.decode(&wrapped.nonce).ok().and_then(|n| n.try_into().ok()).ok_or(VaultError::TeamKeyInvalid)?;
        let ct = B64.decode(&wrapped.ciphertext).map_err(|_| VaultError::TeamKeyInvalid)?;
        let plain = Zeroizing::new(decrypt_with_aad(&key, &ct, &nonce, &ctx).map_err(|_| VaultError::TeamKeyInvalid)?);
        let mut out = Zeroizing::new([0u8; VAULT_KEY_LEN]);
        if plain.len() != VAULT_KEY_LEN {
            return Err(VaultError::TeamKeyInvalid);
        }
        out.copy_from_slice(&plain);
        Ok(out)
    }
}

/// A fresh random key for a new team vault (or a rotation).
pub fn new_team_key() -> TeamKey {
    let mut k = Zeroizing::new([0u8; VAULT_KEY_LEN]);
    OsRng.fill_bytes(k.as_mut());
    k
}

/// Seal a team key for one member's account public key. Bound to the
/// team, the account and the key version, so a copy cannot be replayed
/// for another team, person or version.
pub fn wrap_team_key(key: &[u8; VAULT_KEY_LEN], recipient_public_b64: &str, team_id: Uuid, account_id: &str, key_version: u32) -> Result<WrappedTeamKey> {
    let recipient = b64_32(recipient_public_b64)?;
    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph = PublicKey::from(&eph_secret).to_bytes();
    let shared = Zeroizing::new(eph_secret.diffie_hellman(&PublicKey::from(recipient)).to_bytes());
    if shared.iter().all(|b| *b == 0) {
        // Low-order public key: refuse rather than produce a key anyone knows.
        return Err(VaultError::TeamKeyInvalid);
    }
    let ctx = wrap_context(team_id, account_id, key_version, &recipient, &eph);
    let wrap_key = derive(&shared, &ctx);
    let (ct, nonce) = encrypt_with_aad(&wrap_key, key, &ctx)?;
    Ok(WrappedTeamKey { ephemeral_public_key: B64.encode(eph), nonce: B64.encode(nonce), ciphertext: B64.encode(ct) })
}

impl Vault {
    /// An empty team vault, or the vault in-memory form of one. It uses the
    /// same per-item sync as a personal vault, keyed by the team key.
    pub fn for_team(team_id: Uuid, key: TeamKey) -> Self {
        Vault::from_keyring(Keyring::from_linked_key(KeyringHeader { vault_id: team_id, slots: vec![] }, key))
    }

    /// Reopen a team vault cached on this device (saved with
    /// [`Vault::save`]) with its team key. A wrong or rotated key fails.
    pub fn open_team_cache(file_bytes: &[u8], team_id: Uuid, key: TeamKey) -> Result<Self> {
        let header = Vault::read_header(file_bytes)?;
        if header.vault_id != team_id {
            return Err(VaultError::ItemMismatch);
        }
        Vault::open_with_keyring(file_bytes, Keyring::from_linked_key(header, key))
    }

    /// Trust on first use for members' public keys. Returns `Ok(true)` the
    /// first time an account is seen (and remembers it), `Ok(false)` when
    /// it matches, and an error when the server now offers a different key.
    pub fn check_known_key(&mut self, account_id: &str, public_key_b64: &str) -> Result<bool> {
        match self.known_keys.get(account_id) {
            Some(k) if k == public_key_b64 => Ok(false),
            Some(_) => Err(VaultError::TeamKeyChanged(account_id.to_string())),
            None => {
                self.known_keys.insert(account_id.to_string(), public_key_b64.to_string());
                Ok(true)
            }
        }
    }

    /// After a person compared fingerprints out of band, accept a new key.
    pub fn accept_known_key(&mut self, account_id: &str, public_key_b64: &str) {
        self.known_keys.insert(account_id.to_string(), public_key_b64.to_string());
    }

    pub fn team_key(&self) -> Result<TeamKey> {
        let ring = self.keyring().ok_or(VaultError::NoKeyring)?;
        let mut k = Zeroizing::new([0u8; VAULT_KEY_LEN]);
        k.copy_from_slice(ring.key());
        Ok(k)
    }

    /// Every live record re-encrypted for a rotated team key: the content
    /// to upload in one step with the new key's member copies. Returns the
    /// new vault (already holding the new key) so the caller can switch to
    /// it once the server accepts.
    pub fn rotated_for_team(&self, team_id: Uuid, new_key: TeamKey) -> Result<(Vault, Vec<crate::sync::EncryptedItem>)> {
        let mut next = Vault::for_team(team_id, new_key);
        for r in self.list_records() {
            let mut r = r.clone();
            r.revision = 0;
            r.dirty = true;
            next.records.push(r);
        }
        let items = next.pending_items()?;
        Ok((next, items))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::KdfParams;
    use crate::record::Record;

    fn personal() -> Keyring {
        Keyring::new_with_password("correct horse battery staple", KdfParams::fast_for_tests()).unwrap()
    }

    #[test]
    fn account_key_round_trips_through_the_personal_vault_key() {
        let ring = personal();
        let keys = AccountKeys::generate();
        let stored = keys.store(&ring).unwrap();
        let back = AccountKeys::load(&stored, &ring).unwrap();
        assert_eq!(back.public_key, keys.public_key);
        // Another personal vault cannot open it.
        assert!(AccountKeys::load(&stored, &personal()).is_err());
        // A swapped public key is caught.
        let mut tampered = stored.clone();
        tampered.public_key = AccountKeys::generate().public_key_b64();
        assert!(AccountKeys::load(&tampered, &ring).is_err());
    }

    #[test]
    fn team_key_opens_only_for_the_right_person_team_and_version() {
        let alice = AccountKeys::generate();
        let bob = AccountKeys::generate();
        let team = Uuid::new_v4();
        let key = new_team_key();
        let w = wrap_team_key(&key, &alice.public_key_b64(), team, "alice", 1).unwrap();
        assert_eq!(*alice.unwrap_team_key(&w, team, "alice", 1).unwrap(), *key);
        assert!(bob.unwrap_team_key(&w, team, "alice", 1).is_err());
        assert!(alice.unwrap_team_key(&w, Uuid::new_v4(), "alice", 1).is_err());
        assert!(alice.unwrap_team_key(&w, team, "bob", 1).is_err());
        assert!(alice.unwrap_team_key(&w, team, "alice", 2).is_err());
        // Low-order point is refused.
        assert!(wrap_team_key(&key, &B64.encode([0u8; 32]), team, "x", 1).is_err());
    }

    #[test]
    fn team_vault_items_sync_between_two_members() {
        let team = Uuid::new_v4();
        let key = new_team_key();
        let alice = AccountKeys::generate();
        let bob = AccountKeys::generate();
        let wa = wrap_team_key(&key, &alice.public_key_b64(), team, "a", 1).unwrap();
        let wb = wrap_team_key(&key, &bob.public_key_b64(), team, "b", 1).unwrap();

        let mut va = Vault::for_team(team, alice.unwrap_team_key(&wa, team, "a", 1).unwrap());
        va.add_record({ let mut r = Record::new("KCB corporate"); r.username = "finance@contoso.com".into(); r });
        let items = va.pending_items().unwrap();

        let vb = Vault::for_team(team, bob.unwrap_team_key(&wb, team, "b", 1).unwrap());
        let rec = vb.decrypt_item(&items[0]).unwrap();
        assert_eq!(rec.title, "KCB corporate");

        // Cache on disk and reopen.
        let file = va.save().unwrap();
        let reopened = Vault::open_team_cache(&file, team, alice.unwrap_team_key(&wa, team, "a", 1).unwrap()).unwrap();
        assert_eq!(reopened.list_records().len(), 1);
        assert!(Vault::open_team_cache(&file, team, new_team_key()).is_err());
        assert!(Vault::open_team_cache(&file, Uuid::new_v4(), alice.unwrap_team_key(&wa, team, "a", 1).unwrap()).is_err());
    }

    #[test]
    fn rotation_reencrypts_so_the_old_key_opens_nothing_new() {
        let team = Uuid::new_v4();
        let old = new_team_key();
        let mut v = Vault::for_team(team, Zeroizing::new(*old));
        v.add_record(Record::new("Router"));
        let (next, items) = v.rotated_for_team(team, new_team_key()).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(next.decrypt_item(&items[0]).unwrap().title, "Router");
        let old_vault = Vault::for_team(team, old);
        assert!(old_vault.decrypt_item(&items[0]).is_err());
    }

    #[test]
    fn known_keys_are_pinned() {
        let mut v = Vault::new();
        let k1 = AccountKeys::generate().public_key_b64();
        let k2 = AccountKeys::generate().public_key_b64();
        assert!(v.check_known_key("bob", &k1).unwrap());
        assert!(!v.check_known_key("bob", &k1).unwrap());
        assert!(matches!(v.check_known_key("bob", &k2), Err(VaultError::TeamKeyChanged(_))));
        v.accept_known_key("bob", &k2);
        assert!(!v.check_known_key("bob", &k2).unwrap());
        assert_eq!(fingerprint(&k1).unwrap().len(), 19);
    }
}
