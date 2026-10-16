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
}

pub type Result<T> = std::result::Result<T, VaultError>;
