use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A credential discovered or provided during an engagement. Shared across modules
/// so the rule engine can chain moves (spray → validate → act as that user → …).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Credential {
    pub id: String,
    /// Engagement this belongs to; "" is the implicit global engagement.
    pub engagement_id: String,
    pub domain: String,
    pub username: String,
    /// password | nt_hash | aes_key | ticket
    pub secret_type: String,
    pub secret: String,
    /// Job that discovered this credential, if any.
    pub source_job_id: Option<String>,
    /// Proven to authenticate somewhere.
    pub validated: bool,
    /// "host:service" entries this credential is known to work on.
    pub valid_on: Vec<String>,
    /// unknown | user | admin | da
    pub privilege: String,
    pub created_at: String,
}

impl Credential {
    pub fn new(username: String, secret: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            engagement_id: String::new(),
            domain: String::new(),
            username,
            secret_type: "password".to_string(),
            secret,
            source_job_id: None,
            validated: false,
            valid_on: Vec::new(),
            privilege: "unknown".to_string(),
            created_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        }
    }
}
