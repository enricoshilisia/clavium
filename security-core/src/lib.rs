//! Clavium's vault cryptography. No UI, no network, no knowledge that a
//! desktop app or a server exists — this crate's only job is the one
//! guarantee the whole product depends on: a vault cannot be read without
//! its master password, and can always be read with it.

pub mod crypto;
pub mod error;
pub mod generator;
pub mod kdf;
pub mod keypair;
pub mod record;
pub mod vault;

pub use error::{Result, VaultError};
pub use generator::{generate, generate_passphrase, GeneratorOptions};
pub use kdf::KdfParams;
pub use keypair::{generate_shared_key, wrap_key_for_device, DeviceKeypair, SHARED_KEY_LEN};
pub use record::Record;
pub use vault::Vault;
