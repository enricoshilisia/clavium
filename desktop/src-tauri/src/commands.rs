//! Every Tauri command the React frontend can call. Thin — each one reads
//! as "take the request, call into `clavium_security_core`, reseal if
//! anything changed, return the answer" and nothing more. The actual
//! cryptography and vault logic has no idea Tauri exists, which is the
//! whole point of keeping the security core its own crate.

use std::fs;
use std::path::PathBuf;
use std::sync::MutexGuard;

use clavium_security_core::{
    generate, parse_secret_or_uri, seconds_remaining, totp_now, GeneratorOptions, Record, Vault,
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
    let sealed = session
        .vault
        .seal(&session.master_password)
        .map_err(|e| e.to_string())?;
    fs::write(&session.path, sealed).map_err(|e| format!("could not write vault file: {e}"))?;
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

    let vault = Vault::new();
    let sealed = vault.seal(&master_password).map_err(|e| e.to_string())?;
    fs::write(&path, sealed).map_err(|e| format!("could not write vault file: {e}"))?;

    let summary = VaultSummary {
        record_count: vault.record_count(),
    };
    let mut guard = locked_session(&state)?;
    *guard = Some(VaultSession {
        vault,
        path,
        master_password,
    });
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
    let vault = Vault::unlock(&bytes, &master_password).map_err(|e| e.to_string())?;
    let records = vault.list_records().to_vec();

    let mut guard = locked_session(&state)?;
    *guard = Some(VaultSession {
        vault,
        path,
        master_password,
    });
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

#[tauri::command]
pub fn vault_list_records(state: State<AppState>) -> CmdResult<Vec<Record>> {
    let guard = locked_session(&state)?;
    let session = guard.as_ref().ok_or("no vault is unlocked")?;
    Ok(session.vault.list_records().to_vec())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordInput {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// A pasted otpauth:// URI or bare Base32 secret, or empty for no
    /// authenticator code on this record. Validated eagerly — a typo
    /// caught now, while the person can still see what they pasted, beats
    /// discovering it later as a silent "no code shown" with no error.
    pub totp_secret: Option<String>,
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
    let totp_secret = validated_totp_secret(input.totp_secret)?;
    let mut guard = locked_session(&state)?;
    let session = guard.as_mut().ok_or("no vault is unlocked")?;

    let mut record = Record::new(input.title);
    record.username = input.username;
    record.password = input.password;
    record.url = input.url;
    record.notes = input.notes;
    record.totp_secret = totp_secret;
    session.vault.add_record(record.clone());

    reseal(session)?;
    Ok(record)
}

#[tauri::command]
pub fn vault_update_record(
    state: State<AppState>,
    id: String,
    input: RecordInput,
) -> CmdResult<Record> {
    let id = Uuid::parse_str(&id).map_err(|_| "that is not a valid record id".to_string())?;
    let totp_secret = validated_totp_secret(input.totp_secret)?;
    let mut guard = locked_session(&state)?;
    let session = guard.as_mut().ok_or("no vault is unlocked")?;

    let mut record = Record::new(input.title);
    record.username = input.username;
    record.password = input.password;
    record.url = input.url;
    record.notes = input.notes;
    record.totp_secret = totp_secret;
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
