use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A ranked "next move" surfaced on the war table. Produced by the rule engine
/// from facts + credentials. Carries a copy-paste command and, when auto_runnable,
/// a job_type + job_config so the operator can run it in one click.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Finding {
    pub id: String,
    /// Engagement this belongs to; "" is the implicit global engagement.
    pub engagement_id: String,
    /// Stable key used to upsert/dedup a finding across rule-engine passes.
    pub dedup_key: String,
    pub title: String,
    /// enum | attack | exfil | ad
    pub category: String,
    /// Higher = more valuable; drives ranking on the war table.
    pub value_score: i64,
    /// info | low | medium | high | critical
    pub severity: String,
    pub rationale: String,
    /// Copy-paste command for the operator.
    pub suggested_command: Option<String>,
    pub auto_runnable: bool,
    /// Module to enqueue on one-click run.
    pub job_type: Option<String>,
    pub job_config: serde_json::Value,
    /// suggested | queued | running | done | dismissed
    pub status: String,
    /// JSON references to the facts/creds/hosts that justify this finding.
    pub evidence: serde_json::Value,
    pub created_at: String,
}

impl Finding {
    pub fn new(dedup_key: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            engagement_id: String::new(),
            dedup_key: dedup_key.into(),
            title: title.into(),
            category: String::new(),
            value_score: 0,
            severity: "info".to_string(),
            rationale: String::new(),
            suggested_command: None,
            auto_runnable: false,
            job_type: None,
            job_config: serde_json::json!({}),
            status: "suggested".to_string(),
            evidence: serde_json::json!({}),
            created_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        }
    }
}
