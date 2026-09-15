use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A saved credential/discovery list a brute-force module can load by ID,
/// alongside the existing inline-array and file-path options.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Wordlist {
    pub id: String,
    pub name: String,
    /// "username" | "password" | "discovery"
    pub category: String,
    /// "bundled" | "downloaded" | "custom"
    pub source: String,
    /// Path to the backing file, relative to the process working directory.
    pub file_path: String,
    pub entry_count: i64,
    pub size_bytes: i64,
    pub created_at: String,
}

impl Wordlist {
    pub fn new(
        name: String,
        category: String,
        source: String,
        file_path: String,
        entry_count: i64,
        size_bytes: i64,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            category,
            source,
            file_path,
            entry_count,
            size_bytes,
            created_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        }
    }
}
