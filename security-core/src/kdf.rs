//! Turning a master password into the key that actually encrypts a vault.
//!
//! Argon2id, RFC 9106's own recommendation for a password-hashing /
//! key-derivation use case that needs resistance to both GPU and
//! side-channel attacks — not Argon2i or Argon2d alone, which each trade
//! away one of those.
//!
//! **Parameters are stored per-vault, never assumed.** A vault created
//! today and one created after a future parameter tuning both have to stay
//! openable — the parameters that produced a given vault's key are part of
//! that vault's own file, not a global constant this crate could change out
//! from under an existing user.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, VaultError};

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32; // AES-256

/// The Argon2id parameters a vault was derived with. Conservative
/// defaults aimed at a genuinely slow, deliberate unlock on ordinary
/// hardware — tuned against real target machines before Milestone 1
/// ships, not assumed correct from a table.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost, in KiB.
    pub m_cost: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // 64 MiB, 3 passes, single lane — OWASP's own published Argon2id
        // baseline for a use case this latency-sensitive (a human is
        // waiting for their vault to unlock), not a number picked for
        // being large. Revisited once Milestone 1 has real hardware to
        // benchmark against.
        Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// A derived key, wrapped so it is best-effort zeroed from memory the
/// moment it goes out of scope — the one piece of secret material this
/// crate hands back to a caller, and the one most worth not lingering.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey(pub [u8; KEY_LEN]);

/// Derive the key that encrypts a vault, from the master password and a
/// per-vault random salt. Deterministic given the same three inputs,
/// which is the whole point — unlocking means deriving the same key
/// again, never storing it.
pub fn derive_key(
    master_password: &str,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<DerivedKey> {
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut key)
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

    Ok(DerivedKey(key))
}

/// A fresh random salt for a new vault. Never reused across vaults, and
/// never derived from anything guessable (a username, a timestamp).
pub fn generate_salt() -> [u8; SALT_LEN] {
    use rand::RngCore;
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_password_and_salt_derive_the_same_key() {
        let salt = generate_salt();
        let params = KdfParams::default();
        let a = derive_key("correct horse battery staple", &salt, &params).unwrap();
        let b = derive_key("correct horse battery staple", &salt, &params).unwrap();
        assert_eq!(a.0, b.0);
    }

    #[test]
    fn a_different_password_derives_a_different_key() {
        let salt = generate_salt();
        let params = KdfParams::default();
        let a = derive_key("correct horse battery staple", &salt, &params).unwrap();
        let b = derive_key("wrong password entirely", &salt, &params).unwrap();
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn a_different_salt_derives_a_different_key_from_the_same_password() {
        let params = KdfParams::default();
        let a = derive_key("same password", &generate_salt(), &params).unwrap();
        let b = derive_key("same password", &generate_salt(), &params).unwrap();
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn two_generated_salts_are_never_the_same() {
        // Not a proof, but 16 random bytes colliding twice in a row would
        // indicate a broken RNG, not bad luck.
        assert_ne!(generate_salt(), generate_salt());
    }
}
