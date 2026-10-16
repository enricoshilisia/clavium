use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One stored credential. Deliberately a flat, simple shape for
/// Milestone 0 — secure notes, Wi-Fi credentials and other record kinds
/// the plan calls for are additive fields on this same shape later, not a
/// reason to delay a working vault now.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// A pasted `otpauth://totp/...` URI or bare Base32 secret — see
    /// `crate::otp::parse_secret_or_uri`. `#[serde(default)]` so a vault
    /// sealed before this field existed still deserializes.
    #[serde(default)]
    pub totp_secret: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Record {
    /// A new record, with a fresh id and both timestamps set to now.
    pub fn new(title: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            totp_secret: None,
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_serialized_before_totp_secret_existed_still_deserializes() {
        // Exactly the shape a vault sealed before this field was added
        // would decrypt to — must default to `None`, not fail to parse.
        let old_shape = r#"{
            "id": "11111111-1111-1111-1111-111111111111",
            "title": "Old record",
            "username": "u",
            "password": "p",
            "url": "",
            "notes": "",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }"#;
        let record: Record = serde_json::from_str(old_shape).unwrap();
        assert_eq!(record.totp_secret, None);
    }
}
