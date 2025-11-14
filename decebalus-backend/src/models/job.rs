use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::JobPriority;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Job {
    pub id: String,
    pub job_type: String,
    pub priority: JobPriority,
    pub status: String,
    pub results: Option<String>,
    pub created_at: String,
    pub scheduled_at: Option<i64>,
}

impl Job {
    pub fn new(job_type: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            job_type,
            status: "queued".to_string(),
            priority: JobPriority::NORMAL,
            results: None,
            created_at: String::new(),
            scheduled_at: None,
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

    pub fn is_queued(&self) -> bool {
        self.status == "queued"
    }

    pub fn is_scheduled(&self) -> bool {
        self.status == "scheduled"
    }
}