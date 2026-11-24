//! Clavium's vault cryptography. No UI, no network, no knowledge that a
//! desktop app or a server exists — this crate's only job is the one
//! guarantee the whole product depends on: a vault cannot be read without
//! its master password, and can always be read with it.

pub mod autofill;
pub mod breach;
pub mod categorize;
pub mod crypto;
pub mod error;
pub mod generator;
pub mod health;
pub mod kdf;
pub mod keypair;
pub mod keyring;
pub mod link;
pub mod otp;
pub mod phishing;
pub mod record;
pub mod share;
pub mod sync;
pub mod team;
pub mod vault;

pub use error::{Result, VaultError};
pub use generator::{generate, generate_passphrase, GeneratorOptions};
pub use health::{analyze as analyze_health, HealthReport};
pub use kdf::KdfParams;
pub use keypair::{generate_shared_key, wrap_key_for_device, DeviceKeypair, SHARED_KEY_LEN};
pub use otp::{
    hotp, parse_otpauth_uri, parse_secret_or_uri, seconds_remaining, totp_at, totp_now,
    OtpAlgorithm, TotpParams,
};
pub use categorize::{auto_categorize, category_label, detect_card_brand, suggest_category, CATEGORIES};
pub use keyring::{generate_recovery_key, KeySlot, Keyring, KeyringHeader, SlotKind};
pub use link::{seal_for_link, verification_code, LinkEnvelope, LinkRequest};
pub use phishing::{assess as assess_link, Assessment, Verdict};
pub use record::{CategorySource, CustomField, Record, RecordKind};
pub use sync::{EncryptedItem, MergeReport};
pub use team::{fingerprint, new_team_key, wrap_team_key, AccountKeys, StoredAccountKey, WrappedTeamKey};
pub use vault::Vault;
