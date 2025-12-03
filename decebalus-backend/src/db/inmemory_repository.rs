// src/db/inmemory_repository.rs

use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use crate::db::repository_trait::Repository;
use crate::models::{Job, JobPriority, Host, Config, DisplayStatus, Log};

#[derive(Clone, Default)]
pub struct InMemoryRepository {
    jobs: Arc<Mutex<Vec<Job>>>,
    hosts: Arc<Mutex<Vec<Host>>>,
    logs: Arc<Mutex<Vec<Log>>>,
    config: Arc<Mutex<Config>>,
    display_status: Arc<Mutex<DisplayStatus>>,
}

impl InMemoryRepository {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(Mutex::new(Vec::new())),
            hosts: Arc::new(Mutex::new(Vec::new())),
            logs: Arc::new(Mutex::new(Vec::new())),
            config: Arc::new(Mutex::new(Config { settings: serde_json::Value::Object(Default::default()) })),
            display_status: Arc::new(Mutex::new(DisplayStatus {
                status: "ok".to_string(),
                last_update: Utc::now().to_rfc3339(),
            })),
        }
    }
}

#[async_trait]
impl Repository for InMemoryRepository {
    // ================= JOBS =================
    async fn create_job(&self, job: &Job) -> Result<(), sqlx::Error> {
        let mut jobs = self.jobs.lock().unwrap();
        jobs.push(job.clone());
        Ok(())
    }

    async fn get_job(&self, id: &str) -> Result<Option<Job>, sqlx::Error> {
        let jobs = self.jobs.lock().unwrap();
        Ok(jobs.iter().cloned().find(|j| j.id == id))
    }

    async fn list_jobs(&self) -> Result<Vec<Job>, sqlx::Error> {
        let jobs = self.jobs.lock().unwrap();
        Ok(jobs.clone())
    }

    async fn update_job_status(&self, id: &str, status: &str) -> Result<(), sqlx::Error> {
        let mut jobs = self.jobs.lock().unwrap();
        for job in jobs.iter_mut() {
            if job.id == id {
                job.status = status.to_string();
            }
        }
        Ok(())
    }

    async fn get_running_jobs(&self) -> Result<Vec<Job>, sqlx::Error> {
        let jobs = self.jobs.lock().unwrap();
        Ok(jobs.iter().cloned().filter(|j| j.status == "running").collect())
    }

    async fn get_queued_jobs(&self) -> Result<Vec<Job>, sqlx::Error> {
        let jobs = self.jobs.lock().unwrap();
        Ok(jobs.iter().cloned().filter(|j| j.status == "queued").collect())
    }

    async fn get_scheduled_jobs_due(&self, now: DateTime<Utc>) -> Result<Vec<Job>, sqlx::Error> {
        let jobs = self.jobs.lock().unwrap();
        Ok(jobs.iter().cloned()
            .filter(|j| j.status == "scheduled")
            .filter(|j| {
                j.scheduled_at
                    .map_or(false, |ts| ts < now.timestamp())
            })
            .collect())
    }

    async fn update_job_results(&self, id: &str, results: Option<String>) -> Result<(), sqlx::Error> {
        let mut jobs = self.jobs.lock().unwrap();
        for job in jobs.iter_mut() {
            if job.id == id {
                job.results = results.clone();
            }
        }
        Ok(())
    }

    // ================= HOSTS =================
    async fn upsert_host(&self, host: &Host) -> Result<(), sqlx::Error> {
        let mut hosts = self.hosts.lock().unwrap();
        if let Some(existing) = hosts.iter_mut().find(|h| h.ip == host.ip) {
            *existing = host.clone();
        } else {
            hosts.push(host.clone());
        }
        Ok(())
    }

    async fn get_host(&self, ip: &str) -> Result<Option<Host>, sqlx::Error> {
        let hosts = self.hosts.lock().unwrap();
        Ok(hosts.iter().cloned().find(|h| h.ip == ip))
    }

    async fn list_hosts(&self) -> Result<Vec<Host>, sqlx::Error> {
        let hosts = self.hosts.lock().unwrap();
        Ok(hosts.clone())
    }

    // ================= CONFIG =================
    async fn get_config(&self) -> Result<Config, sqlx::Error> {
        let config = self.config.lock().unwrap();
        Ok(config.clone())
    }

    async fn update_config(&self, config: &Config) -> Result<(), sqlx::Error> {
        let mut cfg = self.config.lock().unwrap();
        *cfg = config.clone();
        Ok(())
    }

    // ================= DISPLAY STATUS =================
    async fn get_display_status(&self) -> Result<DisplayStatus, sqlx::Error> {
        let status = self.display_status.lock().unwrap();
        Ok(status.clone())
    }

    async fn update_display_status(&self, status: &DisplayStatus) -> Result<(), sqlx::Error> {
        let mut current = self.display_status.lock().unwrap();
        *current = status.clone();
        Ok(())
    }

    // ================= LOGS =================
    async fn add_log(
        &self,
        severity: &str,
        service: &str,
        module: Option<&str>,
        job_id: Option<&str>,
        content: &str,
    ) -> Result<(), sqlx::Error> {
        let mut logs = self.logs.lock().unwrap();
        logs.push(Log {
            id: uuid::Uuid::new_v4().to_string(),
            created_at: Utc::now().to_rfc3339(),
            severity: severity.to_string(),
            service: service.to_string(),
            module: module.map(|s| s.to_string()),
            job_id: job_id.map(|s| s.to_string()),
            content: content.to_string(),
        });
        Ok(())
    }

    async fn get_logs(&self) -> Result<Vec<Log>, sqlx::Error> {
        let logs = self.logs.lock().unwrap();
        Ok(logs.clone())
    }

    async fn get_log(&self, id: String) -> Result<Option<Log>, sqlx::Error> {
        let logs = self.logs.lock().unwrap();
        Ok(logs.iter().cloned().find(|l| l.job_id.as_ref() == Some(&id)))
    }

    async fn get_logs_by_job_id(&self, job_id: String) -> Result<Vec<Log>, sqlx::Error> {
        let logs = self.logs.lock().unwrap();
        Ok(logs.iter().cloned()
            .filter(|l| l.job_id.as_ref() == Some(&job_id))
            .collect())
    }

    async fn cleanup_old_logs(&self, days: i64) -> Result<u64, sqlx::Error> {
        let cutoff = Utc::now() - chrono::Duration::days(days);
        let mut logs = self.logs.lock().unwrap();
        let original_len = logs.len();
        logs.retain(|l| {
            DateTime::parse_from_rfc3339(&l.created_at)
                .map(|dt| dt >= cutoff)
                .unwrap_or(true)
        });
        Ok((original_len - logs.len()) as u64)
    }
}
