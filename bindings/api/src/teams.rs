//! Team vault commands (`team_*`), shared by every app.
//!
//! The host does the HTTP; this module holds the unlocked account key and
//! open team vaults, and does every cryptographic step. Commands that
//! change a team vault return its encrypted local cache as `cache`
//! (base64) for the host to store; commands that change the personal vault
//! (remembered member keys) make the caller return `saved` as usual.
//!
//! Flow for a host:
//! 1. After signing in and unlocking: GET /api/teams/key/, then
//!    `team_account_key {account_id, stored}`. If it answers
//!    `status: "created"`, PUT the returned `stored` to the server.
//! 2. GET /api/teams/; for each team with a `wrapped_key`,
//!    `team_open {team_id, key_version, wrapped_key, role, cache}`.
//! 3. Sync each open team like the personal vault: `team_sync_state`,
//!    push `pending`, `team_mark_pushed`, pull, `team_apply_pull`.
//! 4. Managers: for pending members, `team_wrap_for` and POST the grants;
//!    when `needs_rotation`, `team_rotate_prepare`, wrap for each member
//!    with `for_rotation: true`, POST /rotate/, then `team_rotate_commit`.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clavium_security_core::{
    fingerprint, new_team_key, wrap_team_key, AccountKeys, EncryptedItem, Record, StoredAccountKey, Vault, VaultError,
    WrappedTeamKey,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{arg, opt_arg, RecordInput};

struct OpenTeam {
    vault: Vault,
    key_version: u32,
    role: String,
    /// A replacement key prepared by `team_rotate_prepare`, waiting for the
    /// server to accept it.
    rotation: Option<(u32, Vault)>,
}

#[derive(Default)]
pub struct Teams {
    account_id: Option<String>,
    keys: Option<AccountKeys>,
    open: BTreeMap<Uuid, OpenTeam>,
}

fn team_id(a: &Value) -> Result<Uuid, String> {
    arg(a, "team_id")
}

fn cache(v: &Vault) -> Result<String, String> {
    Ok(B64.encode(v.save().map_err(|e| e.to_string())?))
}

impl Teams {
    pub fn lock(&mut self) {
        *self = Teams::default();
    }

    fn keys(&self) -> Result<(&AccountKeys, &str), String> {
        match (&self.keys, &self.account_id) {
            (Some(k), Some(id)) => Ok((k, id.as_str())),
            _ => Err("team vaults are not ready: call team_account_key first".into()),
        }
    }

    fn team(&self, id: Uuid) -> Result<&OpenTeam, String> {
        self.open.get(&id).ok_or_else(|| "that team vault is not open".to_string())
    }

    fn team_mut(&mut self, id: Uuid) -> Result<&mut OpenTeam, String> {
        self.open.get_mut(&id).ok_or_else(|| "that team vault is not open".to_string())
    }

    fn writable(&mut self, id: Uuid) -> Result<&mut OpenTeam, String> {
        let t = self.team_mut(id)?;
        if t.role == "viewer" {
            return Err("you can view this team vault but not change it".into());
        }
        Ok(t)
    }

    /// Returns (result, personal vault changed).
    pub fn dispatch(&mut self, cmd: &str, a: &Value, personal: Option<&mut Vault>) -> Result<(Value, bool), String> {
        let out = match cmd {
            "team_account_key" => {
                let personal = personal.ok_or("vault is locked")?;
                let ring = personal.keyring().ok_or("this vault has no keyring; turn on sync first")?;
                let account_id: String = arg(a, "account_id")?;
                let stored: Option<StoredAccountKey> = opt_arg(a, "stored")?;
                let loaded = stored.as_ref().and_then(|s| AccountKeys::load(s, ring).ok());
                let (keys, status, new_stored) = match loaded {
                    Some(k) => (k, "loaded", None),
                    None => {
                        // None on the server, or made under a personal vault
                        // this device no longer has: a fresh key pair. Team
                        // copies sealed to the old one become pending.
                        let k = AccountKeys::generate();
                        let s = k.store(ring).map_err(|e| e.to_string())?;
                        (k, "created", Some(s))
                    }
                };
                let public = keys.public_key_b64();
                self.keys = Some(keys);
                self.account_id = Some(account_id);
                json!({ "status": status, "stored": new_stored, "public_key": public, "fingerprint": fingerprint(&public).map_err(|e| e.to_string())? })
            }
            "team_fingerprint" => {
                let pk: String = arg(a, "public_key")?;
                json!(fingerprint(&pk).map_err(|e| e.to_string())?)
            }
            "team_create" => {
                let (keys, account_id) = self.keys()?;
                let id = Uuid::new_v4();
                let key = new_team_key();
                let wrapped = wrap_team_key(&key, &keys.public_key_b64(), id, account_id, 1).map_err(|e| e.to_string())?;
                let vault = Vault::for_team(id, key);
                let c = cache(&vault)?;
                self.open.insert(id, OpenTeam { vault, key_version: 1, role: "manager".into(), rotation: None });
                json!({ "team_id": id, "key_version": 1, "wrapped_key": wrapped, "cache": c })
            }
            "team_open" => {
                let id = team_id(a)?;
                let key_version: u32 = arg(a, "key_version")?;
                let role: String = arg(a, "role")?;
                if let Some(t) = self.open.get_mut(&id) {
                    if t.key_version == key_version {
                        t.role = role;
                        return Ok((json!({ "count": t.vault.list_records().len(), "reopened": false }), false));
                    }
                }
                let wrapped: WrappedTeamKey = arg(a, "wrapped_key")?;
                let (keys, account_id) = self.keys()?;
                let key = keys.unwrap_team_key(&wrapped, id, account_id, key_version).map_err(|e| e.to_string())?;
                let cached: Option<String> = opt_arg(a, "cache")?;
                let restored = cached
                    .and_then(|c| B64.decode(c).ok())
                    .and_then(|bytes| Vault::open_team_cache(&bytes, id, zeroize::Zeroizing::new(*key)).ok());
                // A cache from an older key cannot be opened: start empty
                // and pull everything again.
                let fresh = restored.is_none();
                let vault = restored.unwrap_or_else(|| Vault::for_team(id, key));
                let count = vault.list_records().len();
                let c = cache(&vault)?;
                self.open.insert(id, OpenTeam { vault, key_version, role, rotation: None });
                json!({ "count": count, "reopened": true, "fresh": fresh, "cache": c })
            }
            "team_close" => {
                self.open.remove(&team_id(a)?);
                Value::Null
            }
            "team_open_ids" => json!(self.open.keys().collect::<Vec<_>>()),
            "team_list" => {
                let t = self.team(team_id(a)?)?;
                let query: Option<String> = opt_arg(a, "query")?;
                let mut out = t.vault.search(query.as_deref().unwrap_or(""));
                out.sort_by(|x, y| y.favorite.cmp(&x.favorite).then_with(|| x.title.to_lowercase().cmp(&y.title.to_lowercase())));
                serde_json::to_value(out).unwrap()
            }
            "team_get" => {
                let t = self.team(team_id(a)?)?;
                let id: Uuid = arg(a, "id")?;
                serde_json::to_value(t.vault.get_record(id).ok_or("no such record")?).unwrap()
            }
            "team_add" => {
                let t = self.writable(team_id(a)?)?;
                let input: RecordInput = arg(a, "record")?;
                let mut r = Record::new_of_kind(input.kind, "");
                input.apply(&mut r)?;
                let id = r.id;
                t.vault.add_record(r);
                json!({ "record": t.vault.get_record(id), "cache": cache(&t.vault)? })
            }
            "team_update" => {
                let t = self.writable(team_id(a)?)?;
                let id: Uuid = arg(a, "id")?;
                let input: RecordInput = arg(a, "record")?;
                let mut r = t.vault.get_record(id).cloned().ok_or("no such record")?;
                input.apply(&mut r)?;
                t.vault.update_record(id, r).map_err(|e| e.to_string())?;
                json!({ "record": t.vault.get_record(id), "cache": cache(&t.vault)? })
            }
            "team_delete" => {
                let t = self.writable(team_id(a)?)?;
                let id: Uuid = arg(a, "id")?;
                t.vault.delete_record(id).map_err(|e| e.to_string())?;
                json!({ "cache": cache(&t.vault)? })
            }
            "team_sync_state" => {
                let t = self.team(team_id(a)?)?;
                // Viewers never push; the server would refuse anyway.
                let pending = if t.role == "viewer" { vec![] } else { t.vault.pending_items().map_err(|e| e.to_string())? };
                json!({ "cursor": t.vault.sync_cursor(), "pending": pending, "key_version": t.key_version })
            }
            "team_apply_pull" => {
                let t = self.team_mut(team_id(a)?)?;
                let items: Vec<EncryptedItem> = arg(a, "items")?;
                let cursor: u64 = arg(a, "cursor")?;
                let mut records = Vec::with_capacity(items.len());
                for item in &items {
                    records.push(t.vault.decrypt_item(item).map_err(|e| e.to_string())?);
                }
                let report = t.vault.merge_remote(records, cursor);
                json!({ "report": report, "cache": cache(&t.vault)? })
            }
            "team_mark_pushed" => {
                #[derive(Deserialize)]
                struct Accepted {
                    item: EncryptedItem,
                    revision: u64,
                }
                let t = self.team_mut(team_id(a)?)?;
                let accepted: Vec<Accepted> = arg(a, "accepted")?;
                for x in accepted {
                    t.vault.mark_pushed(x.item.id, x.revision, &x.item).map_err(|e| e.to_string())?;
                }
                json!({ "cache": cache(&t.vault)? })
            }
            "team_wrap_for" => {
                let id = team_id(a)?;
                let member: String = arg(a, "account_id")?;
                let public_key: String = arg(a, "public_key")?;
                let trust_new: bool = opt_arg(a, "trust_new")?.unwrap_or(false);
                let for_rotation: bool = opt_arg(a, "for_rotation")?.unwrap_or(false);
                let personal = personal.ok_or("vault is locked")?;
                let fp = fingerprint(&public_key).map_err(|e| e.to_string())?;
                // Your own key needs no pinning; anyone else's is pinned on
                // first sight, and a change must be confirmed by a person.
                let own = self.account_id.as_deref() == Some(member.as_str());
                let mut changed = false;
                let first_seen = if own {
                    false
                } else if trust_new {
                    personal.accept_known_key(&member, &public_key);
                    changed = true;
                    false
                } else {
                    match personal.check_known_key(&member, &public_key) {
                        Ok(first) => {
                            changed = first;
                            first
                        }
                        Err(VaultError::TeamKeyChanged(_)) => {
                            return Err(format!("key_changed: this person's key is different from before (new fingerprint {fp}). Check it with them before sharing."));
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                };
                let t = self.team(id)?;
                let (key, version) = match (&t.rotation, for_rotation) {
                    (Some((v, next)), true) => (next.team_key().map_err(|e| e.to_string())?, *v),
                    (None, true) => return Err("no key replacement is in progress".into()),
                    _ => (t.vault.team_key().map_err(|e| e.to_string())?, t.key_version),
                };
                let wrapped = wrap_team_key(&key, &public_key, id, &member, version).map_err(|e| e.to_string())?;
                return Ok((json!({ "wrapped_key": wrapped, "key_version": version, "fingerprint": fp, "first_seen": first_seen }), changed));
            }
            "team_rotate_prepare" => {
                let id = team_id(a)?;
                let t = self.team_mut(id)?;
                if t.role != "manager" {
                    return Err("only managers can replace the key".into());
                }
                let (next, items) = t.vault.rotated_for_team(id, new_team_key()).map_err(|e| e.to_string())?;
                let version = t.key_version + 1;
                t.rotation = Some((version, next));
                json!({ "key_version": version, "items": items })
            }
            "team_rotate_commit" => {
                let id = team_id(a)?;
                let t = self.team_mut(id)?;
                let (version, next) = t.rotation.take().ok_or("no key replacement is in progress")?;
                // The server stored every item afresh under the new key, so
                // start empty with that key and pull everything from 0
                // (the host does this next) to pick up the new revisions.
                t.vault = Vault::for_team(id, next.team_key().map_err(|e| e.to_string())?);
                t.key_version = version;
                json!({ "key_version": version, "cache": cache(&t.vault)?, "pull_from": 0 })
            }
            "team_rotate_cancel" => {
                self.team_mut(team_id(a)?)?.rotation = None;
                Value::Null
            }
            other => return Err(format!("unknown command: {other}")),
        };
        Ok((out, false))
    }
}
