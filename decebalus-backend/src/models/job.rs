use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Job {
    pub id: String,
    pub job_type: String,
    pub status: String,
    pub results: Option<String>,
}

impl Job {
    pub fn new(job_type: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            job_type,
            status: "queued".to_string(),
            results: None,
        }
    }
    
    pub fn is_running(&self) -> bool {
        self.status == "running"
    }
    
    pub fn is_completed(&self) -> bool {
        self.status == "completed"
    }
    
    pub fn is_cancelled(&self) -> bool {
        self.status == "cancelled"
    }
}