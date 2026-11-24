//! Team vaults on the desktop: one command that forwards to the shared
//! team logic in `clavium-api` (the same code the phone and web app run),
//! with the unlocked personal vault for keys and pins.
//!
//! Team caches (encrypted with the team key) are kept as files in a
//! `teams/` folder next to the personal vault, so the frontend never
//! handles them.

use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::Value;
use tauri::State;

use crate::state::AppState;

fn cache_path(vault_path: &std::path::Path, team_id: &str) -> Option<PathBuf> {
    let id = uuid::Uuid::parse_str(team_id).ok()?;
    Some(vault_path.parent()?.join("teams").join(format!("{id}.clavium")))
}

fn write_atomic(path: &PathBuf, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("could not create team cache folder: {e}"))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| format!("could not write team cache: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("could not replace team cache: {e}"))
}

#[tauri::command]
pub fn team_invoke(state: State<AppState>, cmd: String, mut args: Value) -> Result<Value, String> {
    if !cmd.starts_with("team_") {
        return Err("not a team command".into());
    }
    let mut session = state.session.lock().map_err(|_| "internal error: session lock poisoned")?;
    let session = session.as_mut().ok_or("no vault is unlocked")?;
    let mut teams = state.teams.lock().map_err(|_| "internal error: team lock poisoned")?;
    let team_id = args.get("team_id").and_then(|v| v.as_str()).map(str::to_string);

    if cmd == "team_open" {
        if let Some(path) = team_id.as_deref().and_then(|id| cache_path(&session.path, id)) {
            if let Ok(bytes) = fs::read(&path) {
                args["cache"] = Value::String(B64.encode(bytes));
            }
        }
    }
    if cmd == "team_close_and_forget" {
        if let Some(path) = team_id.as_deref().and_then(|id| cache_path(&session.path, id)) {
            let _ = fs::remove_file(path);
        }
        teams.dispatch("team_close", &args, Some(&mut session.vault))?;
        return Ok(Value::Null);
    }

    let (mut out, personal_changed) = teams.dispatch(&cmd, &args, Some(&mut session.vault))?;
    if personal_changed {
        crate::commands::reseal_session(session)?;
    }
    // team_create answers with the new id rather than taking one.
    let id = team_id.or_else(|| out.get("team_id").and_then(|v| v.as_str()).map(str::to_string));
    if let (Some(cache), Some(id)) = (out.as_object_mut().and_then(|o| o.remove("cache")), id) {
        if let (Some(b64), Some(path)) = (cache.as_str(), cache_path(&session.path, &id)) {
            write_atomic(&path, &B64.decode(b64).map_err(|e| e.to_string())?)?;
        }
    }
    Ok(out)
}
