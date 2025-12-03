use async_trait::async_trait;
use crate::models::{Job, Host, Config, Log, DisplayStatus};
use chrono::{DateTime, Utc};

#[async_trait]
pub trait Repository: Send + Sync {
    // JOBS
    async fn create_job(&self, job: &Job) -> Result<(), sqlx::Error>;
    async fn get_job(&self, id: &str) -> Result<Option<Job>, sqlx::Error>;
    async fn list_jobs(&self) -> Result<Vec<Job>, sqlx::Error>;
    async fn update_job_status(&self, id: &str, status: &str) -> Result<(), sqlx::Error>;
    async fn update_job_results(&self, id: &str, results: Option<String>) -> Result<(), sqlx::Error>;
    async fn get_running_jobs(&self) -> Result<Vec<Job>, sqlx::Error>;
    async fn get_queued_jobs(&self) -> Result<Vec<Job>, sqlx::Error>;
    async fn get_scheduled_jobs_due(&self, now: DateTime<Utc>) -> Result<Vec<Job>, sqlx::Error>;

    // HOSTS
    async fn upsert_host(&self, host: &Host) -> Result<(), sqlx::Error>;
    async fn get_host(&self, ip: &str) -> Result<Option<Host>, sqlx::Error>;
    async fn list_hosts(&self) -> Result<Vec<Host>, sqlx::Error>;

    // CONFIG
    async fn get_config(&self) -> Result<Config, sqlx::Error>;
    async fn update_config(&self, config: &Config) -> Result<(), sqlx::Error>;

    // DISPLAY STATUS
    async fn get_display_status(&self) -> Result<DisplayStatus, sqlx::Error>;
    async fn update_display_status(&self, status: &DisplayStatus) -> Result<(), sqlx::Error>;

    // LOGS
    async fn add_log(&self, severity: &str, service: &str, module: Option<&str>, job_id: Option<&str>, content: &str) -> Result<(), sqlx::Error>;
    async fn get_logs(&self) -> Result<Vec<Log>, sqlx::Error>;
    async fn get_log(&self, id: String) -> Result<Option<Log>, sqlx::Error>;
    async fn get_logs_by_job_id(&self, job_id: String) -> Result<Vec<Log>, sqlx::Error>;
    async fn cleanup_old_logs(&self, days: i64) -> Result<u64, sqlx::Error>;
}
