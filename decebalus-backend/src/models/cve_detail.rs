use serde::{Deserialize, Serialize};

/// Enriched CVE record sourced from the NVD API and cached locally.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CveDetail {
    pub cve_id:           String,
    pub description:      String,
    pub cvss_v3_score:    Option<f64>,
    pub cvss_v3_severity: Option<String>,
    pub cvss_v2_score:    Option<f64>,
    pub cvss_v2_severity: Option<String>,
    pub published_at:     Option<String>,
    /// Reference URLs (CVE advisories, patches, writeups).
    pub references:       Vec<String>,
    pub fetched_at:       String,
}
