use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    #[serde(default = "default_job_type")]
    pub job_type: String,

    // Simple jobs (discovery, port-scan, nmap-scan) pass just a target string.
    pub target: Option<String>,

    // Attack jobs pass a full config object with all parameters.
    #[serde(default)]
    pub config: Option<serde_json::Value>,

    pub scheduled_at: Option<i64>,
}

fn default_job_type() -> String {
    "discovery".to_string()
}
