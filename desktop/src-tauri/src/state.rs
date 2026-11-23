//! What the desktop shell holds in memory while a vault is open.
//!
//! The master password is *not* kept in memory. A v3 vault is encrypted
//! under a random vault key held (zeroized on drop) inside the unlocked
//! `Vault`'s keyring, so every mutation re-saves with `Vault::save()`
//! without the password. Locking drops the vault and with it the key.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use clavium_security_core::Vault;

pub struct VaultSession {
    pub vault: Vault,
    pub path: PathBuf,
}

/// A pairing code shown in the desktop UI, waiting for a browser extension
/// to present it back. Single-use and short-lived on purpose: the code
/// itself is the only thing standing between "this person is looking at
/// their own desktop app" and a token that can query the vault, so it
/// should not be valid for long enough to matter if seen over someone's
/// shoulder.
pub struct PendingPairing {
    pub code: String,
    pub expires_at: Instant,
}

/// One browser extension that has completed pairing. Only the token's hash
/// is kept at rest — the same reasoning as the control plane's own
/// `DeviceToken` — and `origin` is the exact `chrome-extension://…` value
/// the pairing request carried, so later requests get CORS echoed back only
/// to the extension that actually paired, not to anything claiming the
/// right bearer token from a different origin.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PairedExtension {
    pub id: uuid::Uuid,
    pub token_hash: String,
    pub origin: String,
    pub label: String,
    pub paired_at: u64,
}

#[derive(Default)]
pub struct AppState {
    pub session: Mutex<Option<VaultSession>>,
    pub pairing: Mutex<Option<PendingPairing>>,
    pub paired: Mutex<Vec<PairedExtension>>,
}
