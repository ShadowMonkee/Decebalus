use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    #[serde(default = "default_job_type")]
    pub job_type: String,

    // Discovery-specific (optional for now)
    pub target: Option<String>,
    pub scheduled_at: Option<i64>
}

fn default_job_type() -> String {
    "discovery".to_string()
}
