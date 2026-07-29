use serde::{Deserialize, Serialize};

/// A single detected change to a host over time (the change-detection timeline).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct HostEvent {
    pub id: i64,
    pub created_at: String,
    pub host_ip: String,
    /// host_new | host_up | host_down | port_opened | vuln_new
    pub event_type: String,
    pub detail: Option<String>,
    pub severity: Option<String>,
}
