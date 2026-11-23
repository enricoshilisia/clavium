//! One JSON command API over the security core.
//!
//! Request:  `{"cmd": "<name>", "args": {...}}`
//! Response: `{"ok": <value>}` or `{"error": "<message>"}`
//!
//! The host (Flutter via FFI, the PWA via WASM) does all I/O: it reads and
//! writes the sealed vault file and talks HTTP to the control plane. This
//! crate does every security decision: crypto, categorisation, merging.
//! Every command that changes the vault returns the new sealed file as
//! base64 in `saved`, so a host cannot forget to persist a change.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clavium_security_core::{
    analyze_health, category_label, generate, generate_passphrase, parse_otpauth_uri,
    parse_secret_or_uri, seconds_remaining, totp_at, CategorySource, CustomField, EncryptedItem,
    GeneratorOptions, KdfParams, Keyring, KeyringHeader, Record, RecordKind, Vault, CATEGORIES,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

type R = Result<Value, String>;

#[derive(Default)]
pub struct Session {
    vault: Option<Vault>,
    /// A new device waiting for its QR code to be approved.
    link: Option<clavium_security_core::LinkRequest>,
    /// Weak KDF parameters for automated tests only.
    fast_kdf: bool,
}

#[derive(Deserialize)]
struct Request {
    cmd: String,
    #[serde(default)]
    args: Value,
}

#[derive(Deserialize, Default)]
struct RecordInput {
    #[serde(default)]
    kind: RecordKind,
    #[serde(default)]
    title: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    totp_secret: Option<String>,
    #[serde(default)]
    fields: BTreeMap<String, String>,
    #[serde(default)]
    custom_fields: Vec<CustomField>,
    /// None or "" = automatic.
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    favorite: bool,
}

impl RecordInput {
    fn apply(self, r: &mut Record) -> Result<(), String> {
        let totp = match self.totp_secret.filter(|s| !s.trim().is_empty()) {
            Some(s) => {
                parse_secret_or_uri(&s)
                    .map_err(|e| format!("that doesn't look like a valid authenticator secret: {e}"))?;
                Some(s.trim().to_string())
            }
            None => None,
        };
        if self.title.trim().is_empty() {
            return Err("a title is required".into());
        }
        r.kind = self.kind;
        r.title = self.title.trim().to_string();
        r.username = self.username;
        r.password = self.password;
        r.url = self.url.trim().to_string();
        r.notes = self.notes;
        r.totp_secret = totp;
        r.fields = self.fields.into_iter().filter(|(_, v)| !v.is_empty()).collect();
        r.custom_fields = self.custom_fields.into_iter().filter(|f| !f.name.trim().is_empty()).collect();
        match self.category.filter(|c| !c.is_empty()) {
            Some(c) => {
                if category_label(&c).is_none() {
                    return Err(format!("unknown category: {c}"));
                }
                r.category = Some(c);
                r.category_source = CategorySource::User;
            }
            None => r.category_source = CategorySource::Auto,
        }
        r.folder = self.folder.map(|f| f.trim().to_string()).filter(|f| !f.is_empty());
        let mut tags: Vec<String> = self
            .tags
            .into_iter()
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        tags.sort();
        tags.dedup();
        r.tags = tags;
        r.favorite = self.favorite;
        Ok(())
    }
}

fn arg<T: for<'de> Deserialize<'de>>(args: &Value, name: &str) -> Result<T, String> {
    serde_json::from_value(args.get(name).cloned().unwrap_or(Value::Null))
        .map_err(|e| format!("argument `{name}`: {e}"))
}

fn opt_arg<T: for<'de> Deserialize<'de>>(args: &Value, name: &str) -> Result<Option<T>, String> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => serde_json::from_value(v.clone())
            .map(Some)
            .map_err(|e| format!("argument `{name}`: {e}")),
    }
}

fn b64_arg(args: &Value, name: &str) -> Result<Vec<u8>, String> {
    let s: String = arg(args, name)?;
    B64.decode(s.trim()).map_err(|_| format!("argument `{name}` is not valid base64"))
}

fn id_arg(args: &Value) -> Result<Uuid, String> {
    let s: String = arg(args, "id")?;
    Uuid::parse_str(&s).map_err(|_| "that is not a valid record id".into())
}

fn now_unix() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    /// For tests: Argon2 parameters cheap enough to run hundreds of times.
    pub fn with_fast_kdf() -> Self {
        Self { vault: None, link: None, fast_kdf: true }
    }

    fn kdf(&self) -> KdfParams {
        if self.fast_kdf {
            KdfParams::fast_for_tests()
        } else {
            KdfParams::default()
        }
    }

    fn vault(&self) -> Result<&Vault, String> {
        self.vault.as_ref().ok_or_else(|| "the vault is locked".into())
    }

    fn vault_mut(&mut self) -> Result<&mut Vault, String> {
        self.vault.as_mut().ok_or_else(|| "the vault is locked".into())
    }

    fn saved(&self) -> Result<String, String> {
        Ok(B64.encode(self.vault()?.save().map_err(|e| e.to_string())?))
    }

    fn unlocked_summary(&self) -> R {
        let v = self.vault()?;
        Ok(json!({
            "record_count": v.record_count(),
            "vault_id": v.keyring().map(|k| k.vault_id().to_string()),
            "saved": self.saved()?,
        }))
    }

    /// Handle one JSON request string and return the JSON response string.
    pub fn handle(&mut self, request: &str) -> String {
        let out = match serde_json::from_str::<Request>(request) {
            Ok(req) => self.dispatch(&req.cmd, &req.args),
            Err(e) => Err(format!("malformed request: {e}")),
        };
        match out {
            Ok(v) => json!({ "ok": v }).to_string(),
            Err(e) => json!({ "error": e }).to_string(),
        }
    }

    fn dispatch(&mut self, cmd: &str, a: &Value) -> R {
        match cmd {
            "version" => Ok(json!({ "api": 1, "core": env!("CARGO_PKG_VERSION") })),

            // ---- lifecycle ----
            "create" => {
                let pw: String = arg(a, "master_password")?;
                if pw.chars().count() < 10 {
                    return Err("use at least 10 characters for the master password".into());
                }
                self.vault = Some(Vault::create_with_params(&pw, self.kdf()).map_err(|e| e.to_string())?);
                self.unlocked_summary()
            }
            "open" => {
                let file = b64_arg(a, "file")?;
                let pw: String = arg(a, "master_password")?;
                self.vault = Some(Vault::open(&file, &pw).map_err(|e| e.to_string())?);
                self.unlocked_summary()
            }
            "open_with_recovery_key" => {
                let file = b64_arg(a, "file")?;
                let key: String = arg(a, "recovery_key")?;
                self.vault = Some(Vault::open_with_recovery_key(&file, &key).map_err(|e| e.to_string())?);
                self.unlocked_summary()
            }
            "open_with_prf" => {
                let file = b64_arg(a, "file")?;
                let cred: String = arg(a, "credential_id")?;
                let out = b64_arg(a, "prf_output")?;
                self.vault = Some(Vault::open_with_prf(&file, &cred, &out).map_err(|e| e.to_string())?);
                self.unlocked_summary()
            }
            // A new device: the keyring header came from the server.
            "open_from_keyring" => {
                let header: KeyringHeader = arg(a, "header")?;
                let pw: String = arg(a, "master_password")?;
                let ring = Keyring::unlock_with_password(header, &pw).map_err(|e| e.to_string())?;
                self.vault = Some(Vault::from_keyring(ring));
                self.unlocked_summary()
            }
            "read_header" => {
                let file = b64_arg(a, "file")?;
                let h = Vault::read_header(&file).map_err(|e| e.to_string())?;
                Ok(serde_json::to_value(h).unwrap())
            }
            "lock" => {
                self.vault = None;
                Ok(Value::Null)
            }
            "is_unlocked" => Ok(json!(self.vault.is_some())),
            "save" => Ok(json!({ "saved": self.saved()? })),

            // ---- records ----
            "list" => {
                let v = self.vault()?;
                let query: Option<String> = opt_arg(a, "query")?;
                let category: Option<String> = opt_arg(a, "category")?;
                let folder: Option<String> = opt_arg(a, "folder")?;
                let favorites: Option<bool> = opt_arg(a, "favorites_only")?;
                let with_totp: Option<bool> = opt_arg(a, "with_totp_only")?;
                let mut out = v.search(query.as_deref().unwrap_or(""));
                if let Some(c) = category {
                    if c == "uncategorized" {
                        out.retain(|r| r.category.is_none());
                    } else {
                        out.retain(|r| r.category.as_deref() == Some(c.as_str()));
                    }
                }
                if let Some(f) = folder {
                    out.retain(|r| r.folder.as_deref() == Some(f.as_str()));
                }
                if favorites == Some(true) {
                    out.retain(|r| r.favorite);
                }
                if with_totp == Some(true) {
                    out.retain(|r| r.totp_secret.is_some());
                }
                out.sort_by(|x, y| {
                    y.favorite
                        .cmp(&x.favorite)
                        .then_with(|| x.title.to_lowercase().cmp(&y.title.to_lowercase()))
                });
                Ok(serde_json::to_value(out).unwrap())
            }
            "get" => {
                let id = id_arg(a)?;
                let r = self.vault()?.get_record(id).ok_or("no such record")?;
                Ok(serde_json::to_value(r).unwrap())
            }
            "add" => {
                let input: RecordInput = arg(a, "record")?;
                let mut r = Record::new_of_kind(input.kind, "");
                input.apply(&mut r)?;
                let id = r.id;
                let v = self.vault_mut()?;
                v.add_record(r);
                let rec = v.get_record(id).cloned();
                Ok(json!({ "record": rec, "saved": self.saved()? }))
            }
            "update" => {
                let id = id_arg(a)?;
                let input: RecordInput = arg(a, "record")?;
                let v = self.vault_mut()?;
                let mut r = v.get_record(id).cloned().ok_or("no such record")?;
                input.apply(&mut r)?;
                v.update_record(id, r).map_err(|e| e.to_string())?;
                let rec = v.get_record(id).cloned();
                Ok(json!({ "record": rec, "saved": self.saved()? }))
            }
            "toggle_favorite" => {
                let id = id_arg(a)?;
                let v = self.vault_mut()?;
                let mut r = v.get_record(id).cloned().ok_or("no such record")?;
                r.favorite = !r.favorite;
                v.update_record(id, r).map_err(|e| e.to_string())?;
                let rec = v.get_record(id).cloned();
                Ok(json!({ "record": rec, "saved": self.saved()? }))
            }
            "delete" => {
                let id = id_arg(a)?;
                self.vault_mut()?.delete_record(id).map_err(|e| e.to_string())?;
                Ok(json!({ "saved": self.saved()? }))
            }

            // ---- organisation ----
            "categories" => {
                let counts = self.vault.as_ref().map(|v| v.category_counts()).unwrap_or_default();
                let mut list: Vec<Value> = CATEGORIES
                    .iter()
                    .map(|(slug, label)| json!({ "slug": slug, "label": label, "count": counts.get(*slug).copied().unwrap_or(0) }))
                    .collect();
                list.push(json!({ "slug": "uncategorized", "label": "Uncategorised", "count": counts.get("uncategorized").copied().unwrap_or(0) }));
                Ok(Value::Array(list))
            }
            "set_category" => {
                let id = id_arg(a)?;
                let cat: Option<String> = opt_arg(a, "category")?;
                let learn: bool = opt_arg(a, "learn")?.unwrap_or(true);
                self.vault_mut()?
                    .set_category(id, cat.filter(|c| !c.is_empty()), learn)
                    .map_err(|e| e.to_string())?;
                Ok(json!({ "saved": self.saved()? }))
            }
            "kinds" => Ok(Value::Array(
                RecordKind::ALL
                    .iter()
                    .map(|k| json!({ "kind": k, "fields": k.field_names() }))
                    .collect(),
            )),
            "folders" => Ok(json!(self.vault()?.folders())),
            "create_folder" => {
                let name: String = arg(a, "name")?;
                self.vault_mut()?.create_folder(&name);
                Ok(json!({ "saved": self.saved()? }))
            }
            "tags" => Ok(json!(self.vault()?.tags())),
            "health" => {
                let v = self.vault()?;
                let records = v.list_records();
                Ok(serde_json::to_value(analyze_health(records.iter())).unwrap())
            }

            // ---- tools ----
            "generate" => {
                let o = GeneratorOptions {
                    length: opt_arg(a, "length")?.unwrap_or(20),
                    include_upper: opt_arg(a, "upper")?.unwrap_or(true),
                    include_lower: opt_arg(a, "lower")?.unwrap_or(true),
                    include_digits: opt_arg(a, "digits")?.unwrap_or(true),
                    include_symbols: opt_arg(a, "symbols")?.unwrap_or(true),
                };
                generate(&o).map(Value::String).map_err(str::to_string)
            }
            "passphrase" => {
                let words: usize = opt_arg(a, "words")?.unwrap_or(5);
                let sep: String = opt_arg(a, "separator")?.unwrap_or_else(|| "-".into());
                generate_passphrase(words, &sep).map(Value::String).map_err(str::to_string)
            }
            "totp" => {
                let secret: String = arg(a, "secret")?;
                let at: u64 = opt_arg(a, "unix_time")?.unwrap_or_else(now_unix);
                let p = parse_secret_or_uri(&secret).map_err(|e| e.to_string())?;
                Ok(json!({
                    "code": totp_at(&p, at).map_err(|e| e.to_string())?,
                    "seconds_remaining": seconds_remaining(&p, at),
                    "period": p.period_seconds,
                    "digits": p.digits,
                }))
            }
            "parse_otpauth" => {
                let uri: String = arg(a, "uri")?;
                let (label, p) = parse_otpauth_uri(&uri).map_err(|e| e.to_string())?;
                let (issuer, account) = match label.split_once(':') {
                    Some((i, acc)) => (i.trim().to_string(), acc.trim().to_string()),
                    None => (String::new(), label.trim().to_string()),
                };
                Ok(json!({ "label": label, "issuer": issuer, "account": account, "digits": p.digits, "period": p.period_seconds }))
            }
            "password_strength" => {
                let pw: String = arg(a, "password")?;
                let bits = clavium_security_core::health::estimate_bits(&pw);
                Ok(json!({ "bits": bits.round(), "weak": bits < clavium_security_core::health::WEAK_BITS }))
            }

            // ---- key slots ----
            "slots" => {
                let ring = self.vault()?.keyring().ok_or("vault has no keyring")?;
                Ok(serde_json::to_value(&ring.header.slots).unwrap())
            }
            "change_master_password" => {
                let pw: String = arg(a, "new_password")?;
                if pw.chars().count() < 10 {
                    return Err("use at least 10 characters for the master password".into());
                }
                let kdf = self.kdf();
                self.vault_mut()?
                    .change_master_password_with_params(&pw, kdf)
                    .map_err(|e| e.to_string())?;
                Ok(json!({ "saved": self.saved()? }))
            }
            "add_recovery_key" => {
                let (id, key) = self.vault_mut()?.add_recovery_slot("Recovery key").map_err(|e| e.to_string())?;
                Ok(json!({ "slot_id": id, "recovery_key": key.as_str(), "saved": self.saved()? }))
            }
            "add_prf_slot" => {
                let cred: String = arg(a, "credential_id")?;
                let salt = b64_arg(a, "prf_salt")?;
                let out = b64_arg(a, "prf_output")?;
                let label: String = opt_arg(a, "label")?.unwrap_or_else(|| "Passkey".into());
                let id = self
                    .vault_mut()?
                    .add_prf_slot(&cred, &salt, &out, &label)
                    .map_err(|e| e.to_string())?;
                Ok(json!({ "slot_id": id, "saved": self.saved()? }))
            }
            "remove_slot" => {
                let id: Uuid = arg(a, "slot_id")?;
                self.vault_mut()?.remove_slot(id).map_err(|e| e.to_string())?;
                Ok(json!({ "saved": self.saved()? }))
            }

            // ---- QR device linking ----
            // New device: make a one-time key pair; the host shows a QR
            // with `public_key` and `link_secret` and registers only
            // `public_key` with the server.
            "link_begin" => {
                let req = clavium_security_core::LinkRequest::new();
                let out = json!({
                    "public_key": req.public_key_b64(),
                    "link_secret": req.link_secret_b64(),
                    "code": req.verification_code(),
                });
                self.link = Some(req);
                Ok(out)
            }
            // Approving device (unlocked): what to show, from the scanned QR.
            "link_code" => {
                let pk: String = arg(a, "public_key")?;
                let secret: String = arg(a, "link_secret")?;
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                let pk: [u8; 32] = URL_SAFE_NO_PAD
                    .decode(pk.trim())
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or("that QR code is not a Clavium link")?;
                let secret = URL_SAFE_NO_PAD.decode(secret.trim()).map_err(|_| "that QR code is not a Clavium link")?;
                Ok(json!(clavium_security_core::verification_code(&pk, &secret)))
            }
            "link_approve" => {
                let pk: String = arg(a, "public_key")?;
                let secret: String = arg(a, "link_secret")?;
                let ring = self.vault()?.keyring().ok_or("vault has no keyring")?;
                let env = clavium_security_core::seal_for_link(&pk, &secret, ring.vault_id(), ring.key())
                    .map_err(|e| e.to_string())?;
                Ok(serde_json::to_value(env).unwrap())
            }
            // New device: open the envelope and unlock with the account's
            // keyring header (fetched with the token the server issued).
            "link_finish" => {
                let env: clavium_security_core::LinkEnvelope = arg(a, "envelope")?;
                let header: KeyringHeader = arg(a, "header")?;
                let req = self.link.as_ref().ok_or("no device link is in progress")?;
                let (vault_id, key) = req.open(&env).map_err(|e| e.to_string())?;
                if vault_id != header.vault_id {
                    return Err("the approved vault does not match this account's vault".into());
                }
                self.link = None;
                self.vault = Some(Vault::from_keyring(Keyring::from_linked_key(header, key)));
                self.unlocked_summary()
            }
            "link_cancel" => {
                self.link = None;
                Ok(Value::Null)
            }

            // ---- sync ----
            "sync_state" => {
                let v = self.vault()?;
                let ring = v.keyring().ok_or("vault has no keyring")?;
                Ok(json!({
                    "vault_id": ring.vault_id(),
                    "header": ring.header,
                    "cursor": v.sync_cursor(),
                    "pending": v.pending_items().map_err(|e| e.to_string())?,
                }))
            }
            "sync_apply_pull" => {
                let items: Vec<EncryptedItem> = arg(a, "items")?;
                let cursor: u64 = arg(a, "cursor")?;
                let v = self.vault_mut()?;
                let mut records = Vec::with_capacity(items.len());
                for item in &items {
                    records.push(v.decrypt_item(item).map_err(|e| e.to_string())?);
                }
                let report = v.merge_remote(records, cursor);
                Ok(json!({ "report": report, "saved": self.saved()? }))
            }
            "sync_mark_pushed" => {
                #[derive(Deserialize)]
                struct Accepted {
                    item: EncryptedItem,
                    revision: u64,
                }
                let accepted: Vec<Accepted> = arg(a, "accepted")?;
                let v = self.vault_mut()?;
                for x in accepted {
                    v.mark_pushed(x.item.id, x.revision, &x.item).map_err(|e| e.to_string())?;
                }
                Ok(json!({ "saved": self.saved()? }))
            }

            other => Err(format!("unknown command: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(s: &mut Session, cmd: &str, args: Value) -> Value {
        let out: Value = serde_json::from_str(&s.handle(&json!({ "cmd": cmd, "args": args }).to_string())).unwrap();
        if let Some(e) = out.get("error") {
            panic!("{cmd} failed: {e}");
        }
        out["ok"].clone()
    }

    fn call_err(s: &mut Session, cmd: &str, args: Value) -> String {
        let out: Value = serde_json::from_str(&s.handle(&json!({ "cmd": cmd, "args": args }).to_string())).unwrap();
        out["error"].as_str().expect("expected an error").to_string()
    }

    #[test]
    fn full_lifecycle_through_json() {
        let mut s = Session::with_fast_kdf();
        call(&mut s, "create", json!({ "master_password": "a long master password" }));
        let added = call(
            &mut s,
            "add",
            json!({ "record": { "kind": "card", "title": "Visa", "fields": { "number": "4111111111111111" } } }),
        );
        let rec = &added["record"];
        assert_eq!(rec["category"], "banking");
        assert_eq!(rec["fields"]["brand"], "visa");
        let file = added["saved"].as_str().unwrap().to_string();

        call(&mut s, "lock", json!({}));
        assert!(call_err(&mut s, "list", json!({})).contains("locked"));
        assert!(call_err(&mut s, "open", json!({ "file": file, "master_password": "wrong" })).contains("incorrect"));
        call(&mut s, "open", json!({ "file": file, "master_password": "a long master password" }));
        let list = call(&mut s, "list", json!({ "category": "banking" }));
        assert_eq!(list.as_array().unwrap().len(), 1);
        let cats = call(&mut s, "categories", json!({}));
        assert!(cats.as_array().unwrap().iter().any(|c| c["slug"] == "banking" && c["count"] == 1));
    }

    #[test]
    fn sync_between_two_sessions() {
        let mut a = Session::with_fast_kdf();
        call(&mut a, "create", json!({ "master_password": "a long master password" }));
        call(&mut a, "add", json!({ "record": { "title": "GitHub", "url": "github.com", "password": "pw" } }));
        let st = call(&mut a, "sync_state", json!({}));
        let pending = st["pending"].as_array().unwrap().clone();
        assert_eq!(pending.len(), 1);

        // Server accepts at revision 1; device B unlocks from the header.
        let mut b = Session::with_fast_kdf();
        call(&mut b, "open_from_keyring", json!({ "header": st["header"], "master_password": "a long master password" }));
        let mut stored = pending[0].clone();
        stored["revision"] = json!(1);
        call(&mut a, "sync_mark_pushed", json!({ "accepted": [{ "item": pending[0], "revision": 1 }] }));
        assert!(call(&mut a, "sync_state", json!({}))["pending"].as_array().unwrap().is_empty());

        let r = call(&mut b, "sync_apply_pull", json!({ "items": [stored], "cursor": 1 }));
        assert_eq!(r["report"]["added"], 1);
        let list = call(&mut b, "list", json!({}));
        assert_eq!(list[0]["title"], "GitHub");
        assert_eq!(list[0]["category"], "development");
    }

    #[test]
    fn validation_errors_are_messages_not_panics() {
        let mut s = Session::with_fast_kdf();
        assert!(call_err(&mut s, "create", json!({ "master_password": "short" })).contains("10"));
        call(&mut s, "create", json!({ "master_password": "a long master password" }));
        assert!(call_err(&mut s, "add", json!({ "record": { "title": "" } })).contains("title"));
        assert!(call_err(&mut s, "add", json!({ "record": { "title": "x", "totp_secret": "not base32!!" } })).contains("authenticator"));
        assert!(call_err(&mut s, "add", json!({ "record": { "title": "x", "category": "nope" } })).contains("unknown category"));
        assert!(call_err(&mut s, "nope", json!({})).contains("unknown command"));
        let bad: Value = serde_json::from_str(&s.handle("not json")).unwrap();
        assert!(bad["error"].as_str().unwrap().contains("malformed"));
    }

    #[test]
    fn totp_matches_rfc_6238_vector() {
        let mut s = Session::new();
        // RFC 6238 SHA1 secret "12345678901234567890", T=59 -> 94287082 (8 digits)
        let uri = "otpauth://totp/Test:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";
        let out = call(&mut s, "totp", json!({ "secret": uri, "unix_time": 59 }));
        assert_eq!(out["code"], "94287082");
        let parsed = call(&mut s, "parse_otpauth", json!({ "uri": uri }));
        assert_eq!(parsed["issuer"], "Test");
        assert_eq!(parsed["account"], "me");
    }

    #[test]
    fn recovery_key_and_password_change() {
        let mut s = Session::with_fast_kdf();
        call(&mut s, "create", json!({ "master_password": "a long master password" }));
        let rk = call(&mut s, "add_recovery_key", json!({}));
        let key = rk["recovery_key"].as_str().unwrap().to_string();
        let changed = call(&mut s, "change_master_password", json!({ "new_password": "another long password" }));
        let file = changed["saved"].as_str().unwrap().to_string();
        call(&mut s, "lock", json!({}));
        call(&mut s, "open_with_recovery_key", json!({ "file": file, "recovery_key": key }));
        call(&mut s, "lock", json!({}));
        call(&mut s, "open", json!({ "file": file, "master_password": "another long password" }));
        assert_eq!(call(&mut s, "slots", json!({})).as_array().unwrap().len(), 2);
    }
}

#[cfg(test)]
mod link_tests {
    use super::*;

    fn call(s: &mut Session, cmd: &str, args: Value) -> Value {
        let out: Value = serde_json::from_str(&s.handle(&json!({ "cmd": cmd, "args": args }).to_string())).unwrap();
        if let Some(e) = out.get("error") {
            panic!("{cmd} failed: {e}");
        }
        out["ok"].clone()
    }

    #[test]
    fn a_phone_links_a_new_device_by_qr() {
        let mut phone = Session::with_fast_kdf();
        call(&mut phone, "create", json!({ "master_password": "a long master password" }));
        let added = call(&mut phone, "add", json!({ "record": { "title": "KCB", "password": "pw" } }));
        let st = call(&mut phone, "sync_state", json!({}));
        let item = st["pending"][0].clone();
        let _ = added;

        let mut laptop = Session::with_fast_kdf();
        let qr = call(&mut laptop, "link_begin", json!({}));
        let code = call(&mut phone, "link_code", json!({ "public_key": qr["public_key"], "link_secret": qr["link_secret"] }));
        assert_eq!(code, qr["code"], "both screens show the same code");
        let env = call(&mut phone, "link_approve", json!({ "public_key": qr["public_key"], "link_secret": qr["link_secret"] }));
        call(&mut laptop, "link_finish", json!({ "envelope": env, "header": st["header"] }));

        // The laptop can now read the phone's records.
        let mut stored = item.clone();
        stored["revision"] = json!(1);
        call(&mut laptop, "sync_apply_pull", json!({ "items": [stored], "cursor": 1 }));
        assert_eq!(call(&mut laptop, "list", json!({}))[0]["title"], "KCB");
        // And its file still opens with the master password after locking.
        let saved = call(&mut laptop, "save", json!({}))["saved"].clone();
        call(&mut laptop, "lock", json!({}));
        call(&mut laptop, "open", json!({ "file": saved, "master_password": "a long master password" }));
    }

    #[test]
    fn a_link_for_another_vault_is_refused() {
        let mut phone = Session::with_fast_kdf();
        call(&mut phone, "create", json!({ "master_password": "a long master password" }));
        let mut other = Session::with_fast_kdf();
        call(&mut other, "create", json!({ "master_password": "another long password" }));
        let other_header = call(&mut other, "sync_state", json!({}))["header"].clone();

        let mut laptop = Session::with_fast_kdf();
        let qr = call(&mut laptop, "link_begin", json!({}));
        let env = call(&mut phone, "link_approve", json!({ "public_key": qr["public_key"], "link_secret": qr["link_secret"] }));
        let out: Value = serde_json::from_str(&laptop.handle(&json!({ "cmd": "link_finish", "args": { "envelope": env, "header": other_header } }).to_string())).unwrap();
        assert!(out["error"].as_str().unwrap().contains("does not match"));
    }
}
