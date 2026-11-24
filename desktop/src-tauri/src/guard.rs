//! Share links and the phishing guard on the desktop. Same core code as
//! the phone and web app (`security-core` share.rs and phishing.rs).

use clavium_security_core::{assess_link, share, Assessment};
use serde_json::{json, Value};
use tauri::State;
use uuid::Uuid;

use crate::state::AppState;

/// Website addresses in the personal vault and every open team vault.
pub(crate) fn saved_urls(state: &AppState) -> Vec<String> {
    let mut urls: Vec<String> = state
        .session
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.vault.list_records().into_iter().map(|r| r.url).filter(|u| !u.is_empty()).collect()))
        .unwrap_or_default();
    if let Ok(t) = state.teams.lock() {
        urls.extend(t.urls());
    }
    urls
}

pub(crate) fn check(state: &AppState, url: &str) -> Assessment {
    assess_link(url, &saved_urls(state))
}

#[tauri::command]
pub fn check_link(state: State<AppState>, url: String) -> Assessment {
    check(&state, &url)
}

#[tauri::command]
pub fn share_create(
    state: State<AppState>,
    id: Option<String>,
    team_id: Option<String>,
    text: Option<String>,
    title: Option<String>,
    passphrase: Option<String>,
    include_totp: Option<bool>,
) -> Result<Value, String> {
    let payload = if let Some(text) = text {
        share::payload_for_text(title.as_deref().unwrap_or("Shared note"), &text)
    } else {
        let id = Uuid::parse_str(id.as_deref().unwrap_or("")).map_err(|_| "no item chosen")?;
        let record = match team_id.as_deref().map(Uuid::parse_str) {
            Some(Ok(t)) => state.teams.lock().map_err(|_| "busy")?.record(t, id),
            Some(Err(_)) => None,
            None => state.session.lock().map_err(|_| "busy")?.as_ref().ok_or("no vault is unlocked")?.vault.get_record(id).cloned(),
        }
        .ok_or("no such item")?;
        share::payload_for(&record, include_totp.unwrap_or(false))
    };
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&payload).map_err(|e| e.to_string())?);
    let draft = share::create(&bytes, passphrase.as_deref()).map_err(|e| e.to_string())?;
    Ok(json!({ "draft": draft, "rounds": share::PBKDF2_ROUNDS }))
}

// ---- breached passwords (k-anonymity: only 5-character hash prefixes leave) ----

fn all_records(state: &AppState) -> (Vec<clavium_security_core::Record>, Vec<(Uuid, clavium_security_core::Record)>) {
    let personal = state
        .session
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.vault.list_records()))
        .unwrap_or_default();
    let teams = state.teams.lock().map(|t| t.all_records()).unwrap_or_default();
    (personal, teams)
}

#[tauri::command]
pub fn breach_prefixes(state: State<AppState>) -> Vec<String> {
    let (mut recs, teams) = all_records(&state);
    recs.extend(teams.into_iter().map(|(_, r)| r));
    clavium_security_core::breach::prefixes(&recs)
}

#[tauri::command]
pub fn breach_apply(state: State<AppState>, ranges: std::collections::BTreeMap<String, String>) -> Vec<Value> {
    use clavium_security_core::breach::find;
    let (personal, teams) = all_records(&state);
    let mut out: Vec<Value> = find(&personal, &ranges)
        .into_iter()
        .map(|h| json!({ "id": h.id, "title": h.title, "count": h.count, "team_id": null }))
        .collect();
    for (team, r) in teams {
        for h in find(std::slice::from_ref(&r), &ranges) {
            out.push(json!({ "id": h.id, "title": h.title, "count": h.count, "team_id": team }));
        }
    }
    out
}
