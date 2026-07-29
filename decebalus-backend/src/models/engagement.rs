use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One internal / assumed-breach engagement: a named scope (CIDRs) plus optional
/// AD context (domain, DC). The active engagement anchors scope-lock and gives
/// every module/finding an `engagement_id` to hang state off.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Engagement {
    pub id: String,
    pub name: String,
    /// CIDR strings the engagement is authorized to touch (scope-lock).
    pub scope_cidrs: Vec<String>,
    pub domain: Option<String>,
    pub dc_ip: Option<String>,
    /// active | archived
    pub status: String,
    pub created_at: String,
}

impl Engagement {
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            scope_cidrs: Vec::new(),
            domain: None,
            dc_ip: None,
            status: "active".to_string(),
            created_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        }
    }
}
