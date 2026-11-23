//! Per-record sync, without any networking. A client:
//!
//! 1. pulls `changes since sync_cursor` from the server, decrypts each item
//!    with [`Vault::decrypt_item`] and hands them to [`Vault::merge_remote`];
//! 2. pushes [`Vault::pending_items`]; each carries the revision it was
//!    based on, and the server refuses any whose base is stale;
//! 3. calls [`Vault::mark_pushed`] for every accepted item. For a refused
//!    one it pulls again (which merges), then pushes again.
//!
//! Merge rules, chosen so that nothing a person typed is ever silently lost:
//!
//! - Local copy unchanged since last sync: the remote version replaces it.
//! - Both sides changed and the content is identical: nothing to do.
//! - One side deleted, the other edited: the edit wins (a deletion is the
//!   easier thing to repeat than retyping a lost edit).
//! - Both sides edited differently: the newer edit keeps the record; the
//!   older one is kept as a separate "(conflict copy)" record.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{decrypt_with_aad, encrypt_with_aad, NONCE_LEN};
use crate::error::{Result, VaultError};
use crate::record::Record;
use crate::vault::Vault;

/// One record as the server stores it: opaque ciphertext plus the minimum
/// metadata sync needs. The server learns a record's id, that it exists,
/// its size, and whether it is deleted. Nothing else.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedItem {
    pub id: Uuid,
    /// Server-assigned revision this item is at (on pull), or the revision
    /// this change was based on (on push). 0 = new.
    pub revision: u64,
    pub deleted: bool,
    /// base64 AES-GCM nonce and ciphertext of the record JSON.
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeReport {
    pub added: usize,
    pub updated: usize,
    pub deleted: usize,
    /// Records duplicated as "(conflict copy)" because both sides edited.
    pub conflicts: usize,
    /// Incoming items that were already up to date locally.
    pub unchanged: usize,
}

fn item_aad(vault_id: Uuid, record_id: Uuid) -> Vec<u8> {
    let mut aad = b"clavium-item-v1|".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(record_id.as_bytes());
    aad
}

impl Vault {
    pub fn sync_cursor(&self) -> u64 {
        self.sync_cursor
    }

    /// Encrypt one record for the server under the vault key. Sync-only
    /// fields (revision, dirty) are not part of the encrypted content.
    pub fn encrypt_record(&self, record: &Record) -> Result<EncryptedItem> {
        let ring = self.keyring.as_ref().ok_or(VaultError::NoKeyring)?;
        let mut clean = record.clone();
        clean.revision = 0;
        clean.dirty = false;
        let plain = Zeroizing::new(serde_json::to_vec(&clean)?);
        let (ct, nonce) = encrypt_with_aad(ring.key(), &plain, &item_aad(ring.vault_id(), record.id))?;
        Ok(EncryptedItem {
            id: record.id,
            revision: record.revision,
            deleted: record.is_deleted(),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(ct),
        })
    }

    /// Decrypt one item pulled from the server. The id in the ciphertext
    /// must match the id the server filed it under (and the AAD enforces
    /// that cryptographically too), so the server cannot swap records.
    pub fn decrypt_item(&self, item: &EncryptedItem) -> Result<Record> {
        let ring = self.keyring.as_ref().ok_or(VaultError::NoKeyring)?;
        let nonce_vec = B64.decode(&item.nonce).map_err(|_| VaultError::ItemMismatch)?;
        if nonce_vec.len() != NONCE_LEN {
            return Err(VaultError::ItemMismatch);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_vec);
        let ct = B64.decode(&item.ciphertext).map_err(|_| VaultError::ItemMismatch)?;
        let plain = Zeroizing::new(
            decrypt_with_aad(ring.key(), &ct, &nonce, &item_aad(ring.vault_id(), item.id))
                .map_err(|_| VaultError::ItemMismatch)?,
        );
        let mut record: Record = serde_json::from_slice(&plain)?;
        if record.id != item.id || record.is_deleted() != item.deleted {
            return Err(VaultError::ItemMismatch);
        }
        record.revision = item.revision;
        record.dirty = false;
        Ok(record)
    }

    /// Every record (and tombstone) that needs pushing, encrypted, each
    /// carrying the revision it was based on.
    pub fn pending_items(&self) -> Result<Vec<EncryptedItem>> {
        self.records
            .iter()
            .filter(|r| r.dirty || r.revision == 0)
            .map(|r| self.encrypt_record(r))
            .collect()
    }

    /// The server accepted a push of `id` and stored it at `new_revision`.
    /// A synced tombstone has done its job and is dropped. If the record
    /// was edited again while the push was in flight (its content no
    /// longer matches what was pushed), it stays dirty.
    pub fn mark_pushed(&mut self, id: Uuid, new_revision: u64, pushed: &EncryptedItem) -> Result<()> {
        let still_same = match self.records.iter().find(|r| r.id == id) {
            Some(r) => {
                let pushed_record = self.decrypt_item(&EncryptedItem {
                    revision: new_revision,
                    ..pushed.clone()
                })?;
                r.same_content(&pushed_record)
            }
            None => return Ok(()),
        };
        let idx = self.records.iter().position(|r| r.id == id).unwrap();
        self.records[idx].revision = new_revision;
        if still_same {
            self.records[idx].dirty = false;
            if self.records[idx].is_deleted() {
                self.records.remove(idx);
            }
        }
        Ok(())
    }

    /// Merge records pulled from the server (already decrypted, each with
    /// its server revision) and advance the cursor to `new_cursor`.
    pub fn merge_remote(&mut self, remote: Vec<Record>, new_cursor: u64) -> MergeReport {
        let mut report = MergeReport::default();
        for incoming in remote {
            self.merge_one(incoming, &mut report);
        }
        if new_cursor > self.sync_cursor {
            self.sync_cursor = new_cursor;
        }
        report
    }

    fn merge_one(&mut self, mut incoming: Record, report: &mut MergeReport) {
        incoming.dirty = false;
        let Some(idx) = self.records.iter().position(|r| r.id == incoming.id) else {
            if incoming.is_deleted() {
                report.unchanged += 1;
            } else {
                self.records.push(incoming);
                report.added += 1;
            }
            return;
        };

        let local = &self.records[idx];
        // Not newer than what our local copy (or our pending change) is
        // based on: we already have it, often it is our own earlier push.
        if incoming.revision <= local.revision {
            report.unchanged += 1;
            return;
        }

        if !local.dirty {
            if incoming.is_deleted() {
                self.records.remove(idx);
                report.deleted += 1;
            } else {
                self.records[idx] = incoming;
                report.updated += 1;
            }
            return;
        }

        // Local has unpushed changes.
        if local.same_content(&incoming) {
            let r = &mut self.records[idx];
            r.revision = incoming.revision;
            r.dirty = false;
            if r.is_deleted() {
                self.records.remove(idx);
            }
            report.unchanged += 1;
            return;
        }

        match (local.is_deleted(), incoming.is_deleted()) {
            (true, false) => {
                // Deleted here, edited there: keep the edit.
                self.records[idx] = incoming;
                report.updated += 1;
            }
            (false, true) => {
                // Edited here, deleted there: keep ours and re-push it on
                // top of the server's tombstone.
                self.records[idx].revision = incoming.revision;
            }
            (true, true) => {
                self.records.remove(idx);
                report.deleted += 1;
            }
            (false, false) => {
                let local_newer = local.updated_at > incoming.updated_at;
                let (keeper, loser) = if local_newer {
                    let mut keep = self.records[idx].clone();
                    keep.revision = incoming.revision;
                    keep.dirty = true;
                    (keep, incoming)
                } else {
                    (incoming, self.records[idx].clone())
                };
                self.records[idx] = keeper;
                let mut copy = loser;
                copy.id = Uuid::new_v4();
                copy.title = format!("{} (conflict copy)", copy.title);
                copy.revision = 0;
                copy.dirty = true;
                self.records.push(copy);
                report.conflicts += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::KdfParams;
    use crate::keyring::Keyring;
    use chrono::Duration;

    fn vault() -> Vault {
        Vault::create_with_params("pw", KdfParams::fast_for_tests()).unwrap()
    }

    /// A second device: same keyring (as if unlocked from the server copy).
    fn second_device(v: &Vault) -> Vault {
        let ring = Keyring::unlock_with_password(v.keyring().unwrap().header.clone(), "pw").unwrap();
        Vault::from_keyring(ring)
    }

    /// Minimal in-memory server with the same accept/refuse rule as the
    /// real control plane.
    #[derive(Default)]
    struct FakeServer {
        items: Vec<EncryptedItem>,
        counter: u64,
    }

    impl FakeServer {
        fn push(&mut self, item: &EncryptedItem) -> std::result::Result<u64, ()> {
            let current = self.items.iter().find(|i| i.id == item.id).map(|i| i.revision).unwrap_or(0);
            if current != item.revision {
                return Err(());
            }
            self.counter += 1;
            let stored = EncryptedItem { revision: self.counter, ..item.clone() };
            self.items.retain(|i| i.id != item.id);
            self.items.push(stored);
            Ok(self.counter)
        }
        fn pull(&self, since: u64) -> (Vec<EncryptedItem>, u64) {
            (self.items.iter().filter(|i| i.revision > since).cloned().collect(), self.counter)
        }
    }

    fn sync(v: &mut Vault, server: &mut FakeServer) -> MergeReport {
        let (items, cursor) = server.pull(v.sync_cursor());
        let records = items.iter().map(|i| v.decrypt_item(i).unwrap()).collect();
        let report = v.merge_remote(records, cursor);
        for item in v.pending_items().unwrap() {
            if let Ok(rev) = server.push(&item) {
                v.mark_pushed(item.id, rev, &item).unwrap();
            }
        }
        report
    }

    #[test]
    fn a_record_added_on_one_device_appears_on_the_other() {
        let mut a = vault();
        let mut b = second_device(&a);
        let mut server = FakeServer::default();
        let mut r = Record::new("GitHub");
        r.password = "hunter2".into();
        a.add_record(r.clone());
        sync(&mut a, &mut server);
        sync(&mut b, &mut server);
        assert_eq!(b.get_record(r.id).unwrap().password, "hunter2");
        assert!(a.pending_items().unwrap().is_empty());
        assert!(b.pending_items().unwrap().is_empty());
    }

    #[test]
    fn concurrent_edits_keep_both_versions() {
        let mut a = vault();
        let mut b = second_device(&a);
        let mut server = FakeServer::default();
        let r = Record::new("Bank");
        let id = r.id;
        a.add_record(r);
        sync(&mut a, &mut server);
        sync(&mut b, &mut server);

        let mut ra = a.get_record(id).unwrap().clone();
        ra.password = "from-a".into();
        a.update_record(id, ra).unwrap();
        let mut rb = b.get_record(id).unwrap().clone();
        rb.password = "from-b".into();
        b.update_record(id, rb).unwrap();
        // b's edit is later.
        b.records.iter_mut().find(|r| r.id == id).unwrap().updated_at += Duration::seconds(5);

        sync(&mut a, &mut server); // a pushes first, wins the server slot
        let report = sync(&mut b, &mut server); // b's push is stale: merges
        assert_eq!(report.conflicts, 1);
        sync(&mut b, &mut server);
        sync(&mut a, &mut server);

        for v in [&a, &b] {
            let passwords: Vec<String> = v.list_records().into_iter().map(|r| r.password).collect();
            assert!(passwords.contains(&"from-a".to_string()));
            assert!(passwords.contains(&"from-b".to_string()));
            assert_eq!(v.get_record(id).unwrap().password, "from-b", "newer edit keeps the id");
        }
    }

    #[test]
    fn a_deletion_syncs_and_the_tombstone_is_cleaned_up() {
        let mut a = vault();
        let mut b = second_device(&a);
        let mut server = FakeServer::default();
        let r = Record::new("Old");
        let id = r.id;
        a.add_record(r);
        sync(&mut a, &mut server);
        sync(&mut b, &mut server);
        a.delete_record(id).unwrap();
        sync(&mut a, &mut server);
        sync(&mut b, &mut server);
        assert!(b.get_record(id).is_none());
        assert!(a.records.iter().all(|r| r.id != id), "tombstone dropped after sync");
    }

    #[test]
    fn edit_beats_delete() {
        let mut a = vault();
        let mut b = second_device(&a);
        let mut server = FakeServer::default();
        let r = Record::new("Keep me");
        let id = r.id;
        a.add_record(r);
        sync(&mut a, &mut server);
        sync(&mut b, &mut server);
        a.delete_record(id).unwrap();
        let mut rb = b.get_record(id).unwrap().clone();
        rb.notes = "important".into();
        b.update_record(id, rb).unwrap();
        sync(&mut a, &mut server);
        sync(&mut b, &mut server);
        sync(&mut b, &mut server);
        sync(&mut a, &mut server);
        assert_eq!(a.get_record(id).unwrap().notes, "important");
        assert_eq!(b.get_record(id).unwrap().notes, "important");
    }

    #[test]
    fn the_server_cannot_swap_two_records_ciphertexts() {
        let mut a = vault();
        let r1 = Record::new("One");
        let r2 = Record::new("Two");
        a.add_record(r1.clone());
        a.add_record(r2.clone());
        let mut i1 = a.encrypt_record(a.get_record(r1.id).unwrap()).unwrap();
        let i2 = a.encrypt_record(a.get_record(r2.id).unwrap()).unwrap();
        i1.nonce = i2.nonce;
        i1.ciphertext = i2.ciphertext;
        assert!(matches!(a.decrypt_item(&i1), Err(VaultError::ItemMismatch)));
    }

    #[test]
    fn another_vaults_key_cannot_read_items() {
        let a = vault();
        let other = vault();
        let item = a.encrypt_record(&Record::new("Secret")).unwrap();
        assert!(other.decrypt_item(&item).is_err());
    }
}
