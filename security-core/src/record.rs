use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// What kind of thing a record holds. Drives which fields a UI shows and
/// feeds auto-categorisation (a `Card` is finance no matter its title).
/// `#[serde(other)]` on `Login` is not used: an unknown kind from a newer
/// client must fail loudly in tests rather than silently become a login,
/// so new kinds are added here before any client writes them.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    #[default]
    Login,
    BankAccount,
    Card,
    Identity,
    SecureNote,
    Wifi,
    SshKey,
    ApiKey,
    Server,
    Database,
    SoftwareLicense,
    Passkey,
}

impl RecordKind {
    pub const ALL: [RecordKind; 12] = [
        RecordKind::Login,
        RecordKind::BankAccount,
        RecordKind::Card,
        RecordKind::Identity,
        RecordKind::SecureNote,
        RecordKind::Wifi,
        RecordKind::SshKey,
        RecordKind::ApiKey,
        RecordKind::Server,
        RecordKind::Database,
        RecordKind::SoftwareLicense,
        RecordKind::Passkey,
    ];

    /// The type-specific field names a client should offer for this kind,
    /// stored in [`Record::fields`]. Common fields (title, username,
    /// password, url, notes, totp) live on the record itself.
    pub fn field_names(self) -> &'static [&'static str] {
        match self {
            RecordKind::Login => &[],
            RecordKind::BankAccount => &[
                "bank_name",
                "account_name",
                "account_number",
                "branch",
                "swift_bic",
                "iban",
                "pin",
            ],
            RecordKind::Card => &["cardholder", "number", "expiry", "cvv", "pin", "brand"],
            RecordKind::Identity => &[
                "full_name",
                "id_number",
                "passport_number",
                "date_of_birth",
                "phone",
                "email",
                "address",
                "kra_pin",
            ],
            RecordKind::SecureNote => &[],
            RecordKind::Wifi => &["ssid", "security"],
            RecordKind::SshKey => &["private_key", "public_key", "passphrase", "host"],
            RecordKind::ApiKey => &["key", "secret", "environment", "expires"],
            RecordKind::Server => &["hostname", "port", "protocol"],
            RecordKind::Database => &["engine", "hostname", "port", "database", "connection_string"],
            RecordKind::SoftwareLicense => &["product", "license_key", "licensed_to", "seats", "expires"],
            RecordKind::Passkey => &["rp_id", "credential_id", "user_handle", "private_key", "sign_count"],
        }
    }
}

/// Whether a record's category was picked by the auto-categoriser or by a
/// person. A person's choice is never overwritten by a later automatic run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CategorySource {
    #[default]
    Auto,
    User,
}

/// A free-form extra field a person adds to any record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    /// Shown masked by default in a UI, like a password.
    #[serde(default)]
    pub hidden: bool,
}

/// One stored item. Every field added after the original Milestone 0
/// shape carries `#[serde(default)]`, so any vault sealed by an older
/// build still opens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    pub id: Uuid,
    #[serde(default)]
    pub kind: RecordKind,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// A pasted `otpauth://totp/...` URI or bare Base32 secret — see
    /// `crate::otp::parse_secret_or_uri`.
    #[serde(default)]
    pub totp_secret: Option<String>,

    /// Type-specific fields (see [`RecordKind::field_names`]), keyed by
    /// name. A map rather than a struct per kind so a client that does
    /// not know a field yet still round-trips it untouched.
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,

    /// Category slug, see [`crate::categorize::Category`].
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub category_source: CategorySource,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    // --- sync metadata (never shown to a person) ---
    /// The server revision this record was last synced at. 0 = never
    /// synced. Assigned by the server, never invented by a client.
    #[serde(default)]
    pub revision: u64,
    /// Changed locally since the last successful push.
    #[serde(default)]
    pub dirty: bool,
    /// Tombstone. A deleted record is kept (without its secrets) until the
    /// deletion has synced, so other devices learn about it.
    #[serde(default)]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl Record {
    /// A new login record, with a fresh id and both timestamps set to now.
    pub fn new(title: impl Into<String>) -> Self {
        Self::new_of_kind(RecordKind::Login, title)
    }

    pub fn new_of_kind(kind: RecordKind, title: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            kind,
            title: title.into(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            totp_secret: None,
            fields: BTreeMap::new(),
            custom_fields: Vec::new(),
            category: None,
            category_source: CategorySource::Auto,
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created_at: now,
            updated_at: now,
            revision: 0,
            dirty: true,
            deleted_at: None,
        }
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    /// True when two records hold the same user-visible content, ignoring
    /// sync metadata and timestamps. Used by the merge to avoid creating a
    /// conflict copy when two devices made the identical change.
    pub fn same_content(&self, other: &Record) -> bool {
        self.kind == other.kind
            && self.title == other.title
            && self.username == other.username
            && self.password == other.password
            && self.url == other.url
            && self.notes == other.notes
            && self.totp_secret == other.totp_secret
            && self.fields == other.fields
            && self.custom_fields == other.custom_fields
            && self.category == other.category
            && self.folder == other.folder
            && self.tags == other.tags
            && self.favorite == other.favorite
            && self.deleted_at.is_some() == other.deleted_at.is_some()
    }

    /// Turn this record into a tombstone: secrets dropped, id kept.
    pub fn tombstone(&mut self) {
        let now = Utc::now();
        self.title.clear();
        self.username.clear();
        self.password.clear();
        self.url.clear();
        self.notes.clear();
        self.totp_secret = None;
        self.fields.clear();
        self.custom_fields.clear();
        self.tags.clear();
        self.deleted_at = Some(now);
        self.updated_at = now;
        self.dirty = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_serialized_before_totp_secret_existed_still_deserializes() {
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
        assert_eq!(record.kind, RecordKind::Login);
        assert!(record.fields.is_empty());
        assert_eq!(record.revision, 0);
        assert!(!record.dirty);
        assert!(!record.is_deleted());
    }

    #[test]
    fn kinds_serialize_as_snake_case() {
        let json = serde_json::to_string(&RecordKind::BankAccount).unwrap();
        assert_eq!(json, "\"bank_account\"");
    }

    #[test]
    fn tombstoning_drops_secrets_but_keeps_the_id() {
        let mut r = Record::new("Bank");
        r.password = "secret".into();
        r.fields.insert("pin".into(), "1234".into());
        let id = r.id;
        r.tombstone();
        assert_eq!(r.id, id);
        assert!(r.password.is_empty());
        assert!(r.fields.is_empty());
        assert!(r.is_deleted());
        assert!(r.dirty);
    }

    #[test]
    fn same_content_ignores_sync_metadata() {
        let a = Record::new("X");
        let mut b = a.clone();
        b.revision = 9;
        b.dirty = false;
        b.updated_at = Utc::now();
        assert!(a.same_content(&b));
        b.password = "changed".into();
        assert!(!a.same_content(&b));
    }
}
