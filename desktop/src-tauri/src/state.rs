//! What the desktop shell holds in memory while a vault is open.
//!
//! **Known simplification, stated plainly rather than hidden**: the master
//! password is kept in memory (inside `VaultSession`) for as long as the
//! vault stays unlocked, so every mutation can reseal to disk immediately
//! without re-prompting. A derived key, wrapped in the security core's own
//! `Zeroize`d type and never the raw password, is the harder-but-correct
//! version of this — owed before a real release, not pretended to already
//! be here. OS-keychain-backed storage for the derived key is the natural
//! next step once there is a packaged app to integrate it into.

use std::path::PathBuf;
use std::sync::Mutex;

use clavium_security_core::Vault;

pub struct VaultSession {
    pub vault: Vault,
    pub path: PathBuf,
    pub master_password: String,
}

#[derive(Default)]
pub struct AppState {
    pub session: Mutex<Option<VaultSession>>,
}
