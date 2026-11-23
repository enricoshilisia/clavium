//! Every Tauri command the React frontend can call. Thin — each one reads
//! as "take the request, call into `clavium_security_core`, reseal if
//! anything changed, return the answer" and nothing more. The actual
//! cryptography and vault logic has no idea Tauri exists, which is the
//! whole point of keeping the security core its own crate.

use std::fs;
use std::path::PathBuf;
use std::sync::MutexGuard;

use std::collections::BTreeMap;

use clavium_security_core::{
    category_label, generate, parse_secret_or_uri, seconds_remaining, totp_now, CategorySource,
    CustomField, EncryptedItem, GeneratorOptions, MergeReport, Record, RecordKind, Vault, CATEGORIES,
};
use serde::Serialize;
use tauri::State;
use uuid::Uuid;

use crate::state::{AppState, VaultSession};

/// Every error a command can produce, serialized as a plain string to the
/// frontend — the frontend does not need Rust's own error type, only a
/// message to show the person who just typed the wrong master password.
type CmdResult<T> = Result<T, String>;

fn locked_session<'a>(
    state: &'a State<AppState>,
) -> CmdResult<MutexGuard<'a, Option<VaultSession>>> {
    state
        .session
        .lock()
        .map_err(|_| "internal error: vault session lock was poisoned".to_string())
}

fn reseal(session: &VaultSession) -> CmdResult<()> {
    let sealed = session.vault.save().map_err(|e| e.to_string())?;
    // Write to a temp file then rename, so a crash mid-write never leaves
    // a half-written vault where the good one was.
    let tmp = session.path.with_extension("tmp");
    fs::write(&tmp, sealed).map_err(|e| format!("could not write vault file: {e}"))?;
    fs::rename(&tmp, &session.path).map_err(|e| format!("could not replace vault file: {e}"))?;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSummary {
    pub record_count: usize,
}

#[tauri::command]
pub fn vault_exists(path: String) -> bool {
    PathBuf::from(path).exists()
}

/// Create a brand-new, empty vault at `path`, sealed under
/// `master_password`, and open it as the current session — a person who
/// just created a vault expects to be inside it, not prompted to unlock
/// what they were just looking at.
#[tauri::command]
pub fn vault_create(
    state: State<AppState>,
    path: String,
    master_password: String,
) -> CmdResult<VaultSummary> {
    let path = PathBuf::from(path);
    if path.exists() {
        return Err("a file already exists at that location".to_string());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("could not create vault directory: {e}"))?;
    }

    let vault = Vault::create(&master_password).map_err(|e| e.to_string())?;
    let sealed = vault.save().map_err(|e| e.to_string())?;
    fs::write(&path, sealed).map_err(|e| format!("could not write vault file: {e}"))?;

    let summary = VaultSummary {
        record_count: vault.record_count(),
    };
    let mut guard = locked_session(&state)?;
    *guard = Some(VaultSession { vault, path });
    Ok(summary)
}

#[tauri::command]
pub fn vault_unlock(
    state: State<AppState>,
    path: String,
    master_password: String,
) -> CmdResult<Vec<Record>> {
    let path = PathBuf::from(path);
    let bytes =
        fs::read(&path).map_err(|e| format!("could not read vault file: {e}"))?;
    // Opens v1 files too; they are rewritten as v3 right away so the old
    // password-only format does not linger on disk.
    let was_v1 = bytes.get(4) == Some(&1);
    let vault = Vault::open(&bytes, &master_password).map_err(|e| e.to_string())?;
    drop(master_password);
    let records = vault.list_records();

    let mut guard = locked_session(&state)?;
    *guard = Some(VaultSession { vault, path });
    if was_v1 {
        reseal(guard.as_ref().unwrap())?;
    }
    Ok(records)
}

/// Clear the in-memory session — the master password and every decrypted
/// record go with it. The file on disk is already up to date (every
/// mutation reseals immediately), so locking has nothing left to save.
#[tauri::command]
pub fn vault_lock(state: State<AppState>) -> CmdResult<()> {
    let mut guard = locked_session(&state)?;
    *guard = None;
    Ok(())
}

#[tauri::command]
pub fn vault_is_unlocked(state: State<AppState>) -> CmdResult<bool> {
    Ok(locked_session(&state)?.is_some())
}

/// The current vault's sealed bytes, base64-encoded — what "back up to
/// your account" uploads. Read straight from disk rather than re-sealing
/// in memory: every mutation already reseals immediately (see `reseal`),
/// so the file on disk is always the authoritative, current version.
#[tauri::command]
pub fn vault_export_sealed(state: State<AppState>) -> CmdResult<String> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    let guard = locked_session(&state)?;
    let session = guard.as_ref().ok_or("no vault is unlocked")?;
    let bytes = fs::read(&session.path).map_err(|e| format!("could not read vault file: {e}"))?;
    Ok(BASE64.encode(bytes))
}

#[tauri::command]
pub fn vault_list_records(state: State<AppState>) -> CmdResult<Vec<Record>> {
    let guard = locked_session(&state)?;
    let session = guard.as_ref().ok_or("no vault is unlocked")?;
    Ok(session.vault.list_records())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordInput {
    #[serde(default)]
    pub kind: RecordKind,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// A pasted otpauth:// URI or bare Base32 secret, or empty for none.
    /// Validated eagerly so a typo shows while the person can still see it.
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    /// `None` = let auto-categorisation decide; `Some` = the person chose.
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
}

impl RecordInput {
    fn apply_to(self, record: &mut Record, totp_secret: Option<String>) {
        record.kind = self.kind;
        record.title = self.title;
        record.username = self.username;
        record.password = self.password;
        record.url = self.url;
        record.notes = self.notes;
        record.totp_secret = totp_secret;
        record.fields = self.fields.into_iter().filter(|(_, v)| !v.is_empty()).collect();
        record.custom_fields = self.custom_fields;
        match self.category.filter(|c| !c.is_empty()) {
            Some(c) => {
                record.category = Some(c);
                record.category_source = CategorySource::User;
            }
            None => record.category_source = CategorySource::Auto,
        }
        record.folder = self.folder.map(|f| f.trim().to_string()).filter(|f| !f.is_empty());
        record.tags = self
            .tags
            .into_iter()
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        record.tags.sort();
        record.tags.dedup();
        record.favorite = self.favorite;
    }
}

fn validate_category(c: &Option<String>) -> CmdResult<()> {
    if let Some(c) = c.as_ref().filter(|c| !c.is_empty()) {
        if category_label(c).is_none() {
            return Err(format!("unknown category: {c}"));
        }
    }
    Ok(())
}

fn validated_totp_secret(input: Option<String>) -> CmdResult<Option<String>> {
    match input {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => {
            parse_secret_or_uri(&s)
                .map_err(|e| format!("that doesn't look like a valid authenticator secret: {e}"))?;
            Ok(Some(s))
        }
    }
}

#[tauri::command]
pub fn vault_add_record(state: State<AppState>, input: RecordInput) -> CmdResult<Record> {
    let totp_secret = validated_totp_secret(input.totp_secret.clone())?;
    let mut guard = locked_session(&state)?;
    let session = guard.as_mut().ok_or("no vault is unlocked")?;

    validate_category(&input.category)?;
    let mut record = Record::new_of_kind(input.kind, "");
    input.apply_to(&mut record, totp_secret);
    let id = record.id;
    session.vault.add_record(record);

    reseal(session)?;
    Ok(session.vault.get_record(id).cloned().ok_or("record vanished after add")?)
}

#[tauri::command]
pub fn vault_update_record(
    state: State<AppState>,
    id: String,
    input: RecordInput,
) -> CmdResult<Record> {
    let id = Uuid::parse_str(&id).map_err(|_| "that is not a valid record id".to_string())?;
    let totp_secret = validated_totp_secret(input.totp_secret.clone())?;
    let mut guard = locked_session(&state)?;
    let session = guard.as_mut().ok_or("no vault is unlocked")?;

    validate_category(&input.category)?;
    let mut record = session
        .vault
        .get_record(id)
        .cloned()
        .ok_or("no record with that id exists in this vault")?;
    input.apply_to(&mut record, totp_secret);
    session
        .vault
        .update_record(id, record)
        .map_err(|e| e.to_string())?;

    reseal(session)?;
    let updated = session.vault.get_record(id).cloned().ok_or("record vanished after update")?;
    Ok(updated)
}

#[tauri::command]
pub fn vault_delete_record(state: State<AppState>, id: String) -> CmdResult<()> {
    let id = Uuid::parse_str(&id).map_err(|_| "that is not a valid record id".to_string())?;
    let mut guard = locked_session(&state)?;
    let session = guard.as_mut().ok_or("no vault is unlocked")?;

    session.vault.delete_record(id).map_err(|e| e.to_string())?;
    reseal(session)?;
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateInput {
    pub length: usize,
    pub include_upper: bool,
    pub include_lower: bool,
    pub include_digits: bool,
    pub include_symbols: bool,
}

#[tauri::command]
pub fn generate_password(input: GenerateInput) -> CmdResult<String> {
    let options = GeneratorOptions {
        length: input.length,
        include_upper: input.include_upper,
        include_lower: input.include_lower,
        include_digits: input.include_digits,
        include_symbols: input.include_symbols,
    };
    generate(&options).map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
    pub period_seconds: u64,
}

/// Stateless on purpose, like `generate_password` — the frontend already
/// has the record's `totp_secret` in memory from the unlocked vault, so
/// this just needs the secret itself, not a lookup by record id.
#[tauri::command]
pub fn totp_code(secret: String) -> CmdResult<TotpCode> {
    let params = parse_secret_or_uri(&secret).map_err(|e| e.to_string())?;
    let code = totp_now(&params).map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    Ok(TotpCode {
        code,
        seconds_remaining: seconds_remaining(&params, now),
        period_seconds: params.period_seconds,
    })
}

// ---- categories ----

#[derive(Serialize)]
pub struct CategoryInfo {
    pub slug: &'static str,
    pub label: &'static str,
}

#[tauri::command]
pub fn categories_list() -> Vec<CategoryInfo> {
    CATEGORIES
        .iter()
        .map(|(slug, label)| CategoryInfo { slug, label })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KindInfo {
    pub kind: RecordKind,
    pub fields: Vec<&'static str>,
}

#[tauri::command]
pub fn record_kinds() -> Vec<KindInfo> {
    RecordKind::ALL
        .iter()
        .map(|k| KindInfo { kind: *k, fields: k.field_names().to_vec() })
        .collect()
}

/// A person recategorises a record; with `learn`, the rest of that site
/// follows. Returns every record, since others may have moved too.
#[tauri::command]
pub fn vault_set_category(
    state: State<AppState>,
    id: String,
    category: Option<String>,
    learn: bool,
) -> CmdResult<Vec<Record>> {
    let id = Uuid::parse_str(&id).map_err(|_| "that is not a valid record id".to_string())?;
    let mut guard = locked_session(&state)?;
    let session = guard.as_mut().ok_or("no vault is unlocked")?;
    session
        .vault
        .set_category(id, category.filter(|c| !c.is_empty()), learn)
        .map_err(|e| e.to_string())?;
    reseal(session)?;
    Ok(session.vault.list_records())
}

#[tauri::command]
pub fn vault_folders(state: State<AppState>) -> CmdResult<Vec<String>> {
    let guard = locked_session(&state)?;
    let session = guard.as_ref().ok_or("no vault is unlocked")?;
    Ok(session.vault.folders())
}

#[tauri::command]
pub fn vault_change_master_password(state: State<AppState>, new_password: String) -> CmdResult<()> {
    if new_password.chars().count() < 10 {
        return Err("use at least 10 characters".into());
    }
    let mut guard = locked_session(&state)?;
    let session = guard.as_mut().ok_or("no vault is unlocked")?;
    session
        .vault
        .change_master_password(&new_password)
        .map_err(|e| e.to_string())?;
    reseal(session)
}

/// Creates a recovery key slot and returns the key to show exactly once.
#[tauri::command]
pub fn vault_create_recovery_key(state: State<AppState>) -> CmdResult<String> {
    let mut guard = locked_session(&state)?;
    let session = guard.as_mut().ok_or("no vault is unlocked")?;
    let (_, key) = session
        .vault
        .add_recovery_slot("Recovery key")
        .map_err(|e| e.to_string())?;
    reseal(session)?;
    Ok(key.to_string())
}

// ---- sync (the frontend does the HTTP; Rust does every crypto step) ----

/// The keyring header (JSON) to upload so other devices can unlock.
#[tauri::command]
pub fn sync_keyring_header(state: State<AppState>) -> CmdResult<String> {
    let guard = locked_session(&state)?;
    let session = guard.as_ref().ok_or("no vault is unlocked")?;
    let ring = session.vault.keyring().ok_or("vault has no keyring")?;
    serde_json::to_string(&ring.header).map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncState {
    pub vault_id: String,
    pub cursor: u64,
    pub pending: Vec<EncryptedItem>,
}

#[tauri::command]
pub fn sync_state(state: State<AppState>) -> CmdResult<SyncState> {
    let guard = locked_session(&state)?;
    let session = guard.as_ref().ok_or("no vault is unlocked")?;
    let ring = session.vault.keyring().ok_or("vault has no keyring")?;
    Ok(SyncState {
        vault_id: ring.vault_id().to_string(),
        cursor: session.vault.sync_cursor(),
        pending: session.vault.pending_items().map_err(|e| e.to_string())?,
    })
}

#[tauri::command]
pub fn sync_apply_pull(
    state: State<AppState>,
    items: Vec<EncryptedItem>,
    cursor: u64,
) -> CmdResult<MergeReport> {
    let mut guard = locked_session(&state)?;
    let session = guard.as_mut().ok_or("no vault is unlocked")?;
    let mut records = Vec::with_capacity(items.len());
    for item in &items {
        records.push(session.vault.decrypt_item(item).map_err(|e| e.to_string())?);
    }
    let report = session.vault.merge_remote(records, cursor);
    reseal(session)?;
    Ok(report)
}

#[derive(serde::Deserialize)]
pub struct PushResult {
    pub item: EncryptedItem,
    pub revision: u64,
}

#[tauri::command]
pub fn sync_mark_pushed(state: State<AppState>, accepted: Vec<PushResult>) -> CmdResult<()> {
    let mut guard = locked_session(&state)?;
    let session = guard.as_mut().ok_or("no vault is unlocked")?;
    for r in accepted {
        session
            .vault
            .mark_pushed(r.item.id, r.revision, &r.item)
            .map_err(|e| e.to_string())?;
    }
    reseal(session)
}

#[tauri::command]
pub fn vault_health(state: State<AppState>) -> CmdResult<clavium_security_core::HealthReport> {
    let guard = locked_session(&state)?;
    let session = guard.as_ref().ok_or("no vault is unlocked")?;
    let records = session.vault.list_records();
    Ok(clavium_security_core::analyze_health(records.iter()))
}

#[tauri::command]
pub fn vault_category_counts(state: State<AppState>) -> CmdResult<BTreeMap<String, usize>> {
    let guard = locked_session(&state)?;
    let session = guard.as_ref().ok_or("no vault is unlocked")?;
    Ok(session.vault.category_counts())
}

/// A new computer: the keyring header came from the account. Unlock it
/// with the master password, write an (empty) vault file, open it; the
/// frontend then pulls every record.
#[tauri::command]
pub fn vault_restore_from_keyring(
    state: State<AppState>,
    path: String,
    header: String,
    master_password: String,
) -> CmdResult<()> {
    let header: clavium_security_core::KeyringHeader =
        serde_json::from_str(&header).map_err(|e| format!("bad keyring from server: {e}"))?;
    let ring = clavium_security_core::Keyring::unlock_with_password(header, &master_password)
        .map_err(|e| e.to_string())?;
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("could not create vault directory: {e}"))?;
    }
    if path.exists() {
        // Keep whatever was there instead of silently replacing it.
        let backup = path.with_extension(format!("before-restore-{}", chrono_stamp()));
        fs::rename(&path, &backup).map_err(|e| format!("could not move the old vault aside: {e}"))?;
    }
    let session = VaultSession { vault: Vault::from_keyring(ring), path };
    reseal(&session)?;
    *locked_session(&state)? = Some(session);
    Ok(())
}

fn chrono_stamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
