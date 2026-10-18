//! The local bridge a browser extension talks to for autofill.
//!
//! A plain HTTP server, loopback-only, on its own OS thread — entirely
//! outside Tauri's own command system, because the thing calling it is a
//! browser extension's background worker, not this app's own webview.
//!
//! **The security model, stated plainly:**
//! - Bound to `127.0.0.1` only. Never reachable from the network.
//! - A password never leaves the vault for a request that cannot name the
//!   exact record it wants (`/reveal?id=…`), and `/search` — the endpoint a
//!   page's own hostname can reach without the person picking anything —
//!   never returns a password, only which records exist for that site.
//! - Pairing is a short-lived, single-use code shown in *this* app's own
//!   window, typed into the extension by the person looking at both. There
//!   is no way to mint a token without that.
//! - A paired token is useless to a plain web page: CORS only answers the
//!   exact `chrome-extension://…` origin that completed pairing, and a
//!   browser enforces that before any script-level trickery gets a chance
//!   to see the response.
//! - Only the token's hash is ever written to disk — the same reasoning as
//!   the control plane's own `DeviceToken`.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};
use tiny_http::{Header, Method, Response, Server};
use uuid::Uuid;

use crate::state::{AppState, PairedExtension, PendingPairing};

pub const BRIDGE_PORT: u16 = 37849;
const PAIRING_CODE_TTL: Duration = Duration::from_secs(120);
const PAIRING_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // no 0/O/1/I/L

fn paired_file(app: &AppHandle) -> std::path::PathBuf {
    let dir = app
        .path()
        .app_data_dir()
        .expect("app data dir must be resolvable");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("paired_extensions.json")
}

fn load_paired(app: &AppHandle) -> Vec<PairedExtension> {
    let path = paired_file(app);
    let Ok(bytes) = std::fs::read(&path) else {
        return Vec::new();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn save_paired(app: &AppHandle, paired: &[PairedExtension]) {
    let path = paired_file(app);
    if let Ok(bytes) = serde_json::to_vec_pretty(paired) {
        let _ = std::fs::write(path, bytes);
    }
}

fn hash_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The base domain a stored record's URL (or a tab's own URL) resolves to,
/// for comparing the two. `url::Url` rather than hand-rolled string
/// splitting — a credential shown against the wrong host because of a
/// parsing shortcut is a real vulnerability, not a cosmetic bug.
fn extract_host(raw: &str) -> Option<String> {
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    url::Url::parse(&with_scheme)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
}

/// Does a record whose URL resolves to `record_host` belong on a tab whose
/// URL resolves to `tab_host`? Exact match, or the tab is a subdomain of
/// the record's host (a record saved against `google.com` should offer
/// itself on `accounts.google.com`) — deliberately not the other
/// direction, since different subdomains of the same domain are routinely
/// different, unrelated services.
fn hosts_match(record_host: &str, tab_host: &str) -> bool {
    record_host == tab_host || tab_host.ends_with(&format!(".{record_host}"))
}

#[derive(Serialize)]
struct SearchHit {
    id: Uuid,
    title: String,
    username: String,
}

#[derive(Serialize)]
struct RevealResponse {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct PairRequest {
    code: String,
    label: String,
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("valid header")
}

fn cors_headers(origin: Option<&str>) -> Vec<Header> {
    let mut headers = vec![
        header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
        header("Access-Control-Allow-Headers", "Content-Type, Authorization"),
        header("Vary", "Origin"),
    ];
    if let Some(origin) = origin {
        headers.push(header("Access-Control-Allow-Origin", origin));
    }
    headers
}

fn json_response(status: u16, origin: Option<&str>, body: &impl Serialize) -> Response<std::io::Cursor<Vec<u8>>> {
    let payload = serde_json::to_vec(body).unwrap_or_default();
    let mut response = Response::from_data(payload)
        .with_status_code(status)
        .with_header(header("Content-Type", "application/json"));
    for h in cors_headers(origin) {
        response.add_header(h);
    }
    response
}

fn error_response(status: u16, origin: Option<&str>, message: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(status, origin, &serde_json::json!({ "error": message }))
}

/// The bearer token on an incoming request, if any — raw, not yet checked
/// against anything.
fn bearer_token(headers: &[Header]) -> Option<String> {
    headers
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("authorization"))
        .and_then(|h| h.value.as_str().strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

fn request_origin(headers: &[Header]) -> Option<String> {
    headers
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("origin"))
        .map(|h| h.value.as_str().to_string())
}

/// Look up which paired extension (if any) a request's bearer token
/// belongs to. The token is the real secret — a random value handed out
/// only after someone typed a short-lived code shown on this app's own
/// screen, which nothing can guess or intercept remotely. The Origin
/// header, when a browser sends one, is checked too as a second factor
/// (a token replayed from a different origin is refused even if it
/// hash-matches) — but it is not required, because a browser extension
/// fetching a URL it was granted via `host_permissions` is not bound by
/// the same page-level CORS rules an ordinary website's script is, and in
/// practice does not always send one. Requiring it here would not be a
/// stronger check, since a page without extension-granted permissions
/// could never complete this fetch in the first place — it would just
/// break the legitimate case.
fn authenticate(app: &AppHandle, headers: &[Header]) -> Option<PairedExtension> {
    let token = bearer_token(headers)?;
    let origin = request_origin(headers);
    let hash = hash_token(&token);
    let state = app.state::<AppState>();
    let paired = state.paired.lock().ok()?;
    paired
        .iter()
        .find(|p| p.token_hash == hash && origin.as_ref().is_none_or(|o| *o == p.origin))
        .cloned()
}

fn handle_pair(app: &AppHandle, body: &str, origin: Option<String>) -> Response<std::io::Cursor<Vec<u8>>> {
    let Some(origin) = origin else {
        return error_response(400, None, "missing Origin header");
    };
    let Ok(req) = serde_json::from_str::<PairRequest>(body) else {
        return error_response(400, Some(&origin), "malformed pairing request");
    };

    let state = app.state::<AppState>();
    let valid = {
        let mut pending = state.pairing.lock().unwrap();
        match pending.as_ref() {
            Some(p) if p.code == req.code.trim().to_uppercase() && Instant::now() < p.expires_at => {
                *pending = None; // single-use
                true
            }
            _ => false,
        }
    };
    if !valid {
        return error_response(401, Some(&origin), "pairing code is wrong or has expired");
    }

    let raw_token = Uuid::new_v4().to_string();
    let entry = PairedExtension {
        id: Uuid::new_v4(),
        token_hash: hash_token(&raw_token),
        origin: origin.clone(),
        label: if req.label.trim().is_empty() { "Browser extension".to_string() } else { req.label.trim().to_string() },
        paired_at: now_unix(),
    };

    {
        let mut paired = state.paired.lock().unwrap();
        paired.push(entry);
        save_paired(app, &paired);
    }

    json_response(201, Some(&origin), &serde_json::json!({ "token": raw_token }))
}

fn handle_status(app: &AppHandle, origin: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let state = app.state::<AppState>();
    let unlocked = state.session.lock().map(|g| g.is_some()).unwrap_or(false);
    json_response(200, Some(origin), &serde_json::json!({ "unlocked": unlocked }))
}

fn handle_search(app: &AppHandle, origin: &str, query: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let tab_host = match query_param(query, "host").and_then(|h| extract_host(&h)) {
        Some(h) => h,
        None => return error_response(400, Some(origin), "missing or unparseable host parameter"),
    };

    let state = app.state::<AppState>();
    let guard = state.session.lock().unwrap();
    let Some(session) = guard.as_ref() else {
        return error_response(423, Some(origin), "vault is locked");
    };

    let hits: Vec<SearchHit> = session
        .vault
        .list_records()
        .iter()
        .filter_map(|r| {
            let record_host = extract_host(&r.url)?;
            hosts_match(&record_host, &tab_host).then(|| SearchHit {
                id: r.id,
                title: r.title.clone(),
                username: r.username.clone(),
            })
        })
        .collect();

    json_response(200, Some(origin), &hits)
}

fn handle_reveal(app: &AppHandle, origin: &str, query: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let Some(id) = query_param(query, "id").and_then(|s| Uuid::parse_str(&s).ok()) else {
        return error_response(400, Some(origin), "missing or invalid id parameter");
    };

    let state = app.state::<AppState>();
    let guard = state.session.lock().unwrap();
    let Some(session) = guard.as_ref() else {
        return error_response(423, Some(origin), "vault is locked");
    };

    match session.vault.get_record(id) {
        Some(record) => json_response(
            200,
            Some(origin),
            &RevealResponse { username: record.username.clone(), password: record.password.clone() },
        ),
        None => error_response(404, Some(origin), "no such record"),
    }
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            urlencoding_decode(v)
        } else {
            None
        }
    })
}

fn urlencoding_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex_byte = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?, 16).ok()?;
                out.push(hex_byte);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Start the bridge server on its own OS thread. Called once from `run()`;
/// the thread lives for the lifetime of the app.
pub fn spawn(app: AppHandle) {
    {
        let paired = load_paired(&app);
        *app.state::<AppState>().paired.lock().unwrap() = paired;
    }

    std::thread::spawn(move || {
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, BRIDGE_PORT);
        let server = match Server::http(addr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("bridge: could not bind 127.0.0.1:{BRIDGE_PORT}: {e}");
                return;
            }
        };

        for request in server.incoming_requests() {
            let origin = request_origin(request.headers());
            let path = request.url().to_string();
            let (path, query) = path.split_once('?').unwrap_or((path.as_str(), ""));
            let method = request.method().clone();

            if method == Method::Options {
                let mut response = Response::from_string("").with_status_code(204);
                for h in cors_headers(origin.as_deref()) {
                    response.add_header(h);
                }
                let _ = request.respond(response);
                continue;
            }

            let response = match (method.clone(), path) {
                (Method::Post, "/pair") => {
                    let mut body = String::new();
                    let mut req = request;
                    let _ = req.as_reader().read_to_string(&mut body);
                    let resp = handle_pair(&app, &body, origin.clone());
                    let _ = req.respond(resp);
                    continue;
                }
                (Method::Get, "/status") => match authenticate(&app, request.headers()) {
                    Some(_) => handle_status(&app, origin.as_deref().unwrap_or("")),
                    None => error_response(401, origin.as_deref(), "not paired"),
                },
                (Method::Get, "/search") => match authenticate(&app, request.headers()) {
                    Some(_) => handle_search(&app, origin.as_deref().unwrap_or(""), query),
                    None => error_response(401, origin.as_deref(), "not paired"),
                },
                (Method::Get, "/reveal") => match authenticate(&app, request.headers()) {
                    Some(_) => handle_reveal(&app, origin.as_deref().unwrap_or(""), query),
                    None => error_response(401, origin.as_deref(), "not paired"),
                },
                _ => error_response(404, origin.as_deref(), "no such endpoint"),
            };
            let _ = request.respond(response);
        }
    });
}

#[tauri::command]
pub fn bridge_generate_pairing_code(state: tauri::State<AppState>) -> Result<String, String> {
    let mut rng = rand::thread_rng();
    let code: String = (0..6)
        .map(|_| PAIRING_ALPHABET[rng.gen_range(0..PAIRING_ALPHABET.len())] as char)
        .collect();
    *state.pairing.lock().map_err(|_| "lock poisoned")? = Some(PendingPairing {
        code: code.clone(),
        expires_at: Instant::now() + PAIRING_CODE_TTL,
    });
    Ok(code)
}

#[derive(Serialize)]
pub struct PairedExtensionView {
    pub id: Uuid,
    pub label: String,
    pub paired_at: u64,
}

#[tauri::command]
pub fn bridge_list_paired(state: tauri::State<AppState>) -> Result<Vec<PairedExtensionView>, String> {
    let paired = state.paired.lock().map_err(|_| "lock poisoned")?;
    Ok(paired
        .iter()
        .map(|p| PairedExtensionView { id: p.id, label: p.label.clone(), paired_at: p.paired_at })
        .collect())
}

#[tauri::command]
pub fn bridge_revoke_paired(app: AppHandle, id: Uuid) -> Result<(), String> {
    let state = app.state::<AppState>();
    let mut paired = state.paired.lock().map_err(|_| "lock poisoned")?;
    paired.retain(|p| p.id != id);
    save_paired(&app, &paired);
    Ok(())
}
