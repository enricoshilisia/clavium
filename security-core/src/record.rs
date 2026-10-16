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
            created_at: now,
            updated_at: now,
        }
    }
}
