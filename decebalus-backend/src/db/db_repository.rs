// src/db/db_repository.rs

use async_trait::async_trait;
use sqlx::SqlitePool;
use crate::db::repository_trait::Repository;
use crate::models::{Job, JobPriority, Host, Config, DisplayStatus, Log};
use chrono::DateTime;
use chrono::Utc;

/// Concrete DB repository
pub struct DbRepository {
    pub pool: SqlitePool,
}

impl DbRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl Repository for DbRepository {
    // ================= JOBS =================
    async fn create_job(&self, job: &Job) -> Result<(), sqlx::Error> {
        crate::db::repository::create_job(&self.pool, job).await
    }

    async fn get_job(&self, id: &str) -> Result<Option<Job>, sqlx::Error> {
        crate::db::repository::get_job(&self.pool, id).await
    }

    async fn list_jobs(&self) -> Result<Vec<Job>, sqlx::Error> {
        crate::db::repository::list_jobs(&self.pool).await
    }

    async fn update_job_status(&self, id: &str, status: &str) -> Result<(), sqlx::Error> {
        crate::db::repository::update_job_status(&self.pool, id, status).await
    }

    async fn get_running_jobs(&self) -> Result<Vec<Job>, sqlx::Error> {
        crate::db::repository::get_running_jobs(&self.pool).await
    }

    async fn get_queued_jobs(&self) -> Result<Vec<Job>, sqlx::Error> {
        crate::db::repository::get_queued_jobs(&self.pool).await
    }

    async fn get_scheduled_jobs_due(&self, now: DateTime<Utc>) -> Result<Vec<Job>, sqlx::Error> {
        crate::db::repository::get_scheduled_jobs_due(&self.pool, now).await
    }

    async fn update_job_results(&self, id: &str, results: Option<String>) -> Result<(), sqlx::Error> {
        crate::db::repository::update_job_results(&self.pool, id, results).await
    }

    // ================= HOSTS =================
    async fn upsert_host(&self, host: &Host) -> Result<(), sqlx::Error> {
        crate::db::repository::upsert_host(&self.pool, host).await
    }

    async fn get_host(&self, ip: &str) -> Result<Option<Host>, sqlx::Error> {
        crate::db::repository::get_host(&self.pool, ip).await
    }

    async fn list_hosts(&self) -> Result<Vec<Host>, sqlx::Error> {
        crate::db::repository::list_hosts(&self.pool).await
    }

    // ================= CONFIG =================
    async fn get_config(&self) -> Result<Config, sqlx::Error> {
        crate::db::repository::get_config(&self.pool).await
    }

    async fn update_config(&self, config: &Config) -> Result<(), sqlx::Error> {
        crate::db::repository::update_config(&self.pool, config).await
    }

    // ================= DISPLAY STATUS =================
    async fn get_display_status(&self) -> Result<DisplayStatus, sqlx::Error> {
        crate::db::repository::get_display_status(&self.pool).await
    }

    async fn update_display_status(&self, status: &DisplayStatus) -> Result<(), sqlx::Error> {
        crate::db::repository::update_display_status(&self.pool, status).await
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
        crate::db::repository::add_log(&self.pool, severity, service, module, job_id, content).await
    }

    async fn get_logs(&self) -> Result<Vec<Log>, sqlx::Error> {
        crate::db::repository::get_logs(&self.pool).await
    }

    async fn get_log(&self, id: String) -> Result<Option<Log>, sqlx::Error> {
        crate::db::repository::get_log(&self.pool, id).await
    }

    async fn get_logs_by_job_id(&self, job_id: String) -> Result<Vec<Log>, sqlx::Error> {
        crate::db::repository::get_logs_by_job_id(&self.pool, job_id).await
    }

    async fn cleanup_old_logs(&self, days: i64) -> Result<u64, sqlx::Error> {
        crate::db::repository::cleanup_old_logs(&self.pool, days).await
    }
}
