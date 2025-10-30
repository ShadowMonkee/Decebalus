use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Log {
    pub id: String,
    pub created_at: String,
    pub severity: String,
    pub service: String,
    pub module: Option<String>,
    pub job_id: Option<String>,
    pub content: String,
}

impl Log {
    pub fn new(id: String, created_at: String, severity: String, service: String, module: Option<String>,job_id: Option<String>, content: String) -> Self {
        Self {
            id,
            created_at,
            severity,
            service,
            module,
            job_id,
            content
        }
    }
}