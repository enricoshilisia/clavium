use thiserror::Error;

/// Every way a vault operation can fail, named specifically rather than
/// collapsed into one generic error — "wrong password" and "the file is
/// corrupt" are different problems for a caller (and eventually a UI) to
/// react to differently.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("the master password is incorrect, or this file is not a Clavium vault")]
    IncorrectPasswordOrCorruptFile,

    #[error("vault file is too short to be valid")]
    TruncatedFile,

    #[error("vault file does not start with the Clavium magic bytes")]
    NotAClaviumVault,

    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u8),

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed — this usually means the wrong password")]
    Decryption,

    #[error("record serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("no record with that id exists in this vault")]
    RecordNotFound,

    #[error("no key slot with that id exists in this vault")]
    SlotNotFound,

    #[error("the last master-password slot cannot be removed")]
    LastPasswordSlot,

    #[error("this vault has no unlocked key; open it with Vault::open first")]
    NoKeyring,

    #[error("this QR code link is invalid, expired, or was not approved by your own device")]
    LinkInvalid,

    #[error("unknown category: {0}")]
    UnknownCategory(String),

    #[error("encrypted item belongs to a different record or vault")]
    ItemMismatch,

    #[error("this team vault key could not be opened (it was made for another account, team or key version)")]
    TeamKeyInvalid,

    #[error("the server offered a different key for account {0} than before; compare fingerprints before sharing")]
    TeamKeyChanged(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;
