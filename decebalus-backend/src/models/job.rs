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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::JobPriority;

    #[test]
    fn new_initializes_correctly() {
        let job = Job::new("scan".into());

        assert_eq!(job.job_type, "scan");
        assert_eq!(job.status, "queued");
        assert_eq!(job.priority, JobPriority::NORMAL);
        assert!(job.results.is_none());
        assert!(job.created_at.is_empty());
        assert!(job.scheduled_at.is_none());

        // ID should not be empty
        assert!(!job.id.is_empty());
    }

    #[test]
    fn uuid_is_unique() {
        let job1 = Job::new("scan".into());
        let job2 = Job::new("scan".into());

        assert_ne!(job1.id, job2.id);
    }

    #[test]
    fn status_checks_work() {
        let mut job = Job::new("scan".into());

        // Initially queued
        assert!(job.is_queued());
        assert!(!job.is_running());
        assert!(!job.is_completed());
        assert!(!job.is_cancelled());
        assert!(!job.is_scheduled());

        // Running
        job.status = "running".into();
        assert!(job.is_running());

        // Completed
        job.status = "completed".into();
        assert!(job.is_completed());

        // Cancelled
        job.status = "cancelled".into();
        assert!(job.is_cancelled());

        // Scheduled
        job.status = "scheduled".into();
        assert!(job.is_scheduled());
    }

    #[test]
    fn results_can_be_stored() {
        let mut job = Job::new("scan".into());
        job.results = Some("OK".to_string());

        assert_eq!(job.results.unwrap(), "OK");
    }


}
