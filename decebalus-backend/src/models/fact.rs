use serde::{Deserialize, Serialize};

/// A single observation about a subject (host, domain, credential, share). The
/// generic key/JSON-value shape lets new checks add facts without a migration;
/// the rule engine reads facts to produce findings.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Fact {
    pub id: i64,
    /// Engagement this belongs to; "" is the implicit global engagement.
    pub engagement_id: String,
    /// host | domain | cred | share
    pub subject_type: String,
    /// Identifier of the subject (an IP, a domain FQDN, …).
    pub subject_id: String,
    /// e.g. smb_signing, null_session, adcs_present, roastable_spn.
    pub key: String,
    pub value: serde_json::Value,
    pub source_job_id: Option<String>,
    pub created_at: String,
}

impl Fact {
    /// Build a fact ready to upsert (id/created_at are assigned by the DB).
    pub fn new(
        subject_type: impl Into<String>,
        subject_id: impl Into<String>,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        Self {
            id: 0,
            engagement_id: String::new(),
            subject_type: subject_type.into(),
            subject_id: subject_id.into(),
            key: key.into(),
            value,
            source_job_id: None,
            created_at: String::new(),
        }
    }
}
