// tests/job_executor_tests.rs

use std::sync::Arc;

use tokio::sync::{broadcast, Semaphore};

use decebalus_backend::db::repository;
use decebalus_backend::services::job_executor::JobExecutor;
use decebalus_backend::state::AppState;
use decebalus_backend::models::{Job, JobPriority};

async fn test_state() -> Arc<AppState> {
    let (tx, _rx) = broadcast::channel(32);

    let db_pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:")
        .await
        .expect("failed to create in-memory DB");

    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .expect("Failed to run migrations");

    let state = AppState {
        broadcaster: tx,
        db: db_pool,
        max_threads: 5,
        semaphore: Arc::new(Semaphore::new(5)),
    };

    Arc::new(state)
}

#[tokio::test]
async fn scenario_job_executor_runs_discovery_successfully() {
    let state = test_state().await;

    let mut job = Job::new("discovery".into());
    job.id = "job1".into();
    job.config = serde_json::json!({"target": "127.0.0.1/32"});

    repository::create_job(&state.db, &job).await.unwrap();

    let permit = state.semaphore.clone().acquire_owned().await.unwrap();
    JobExecutor::execute_job(job.clone(), state.clone(), permit).await;

    let updated = repository::get_job(&state.db, "job1").await.unwrap().unwrap();

    assert_eq!(updated.status, "completed");
    assert!(updated.results.is_some());
    assert!(updated.results.as_ref().unwrap().contains("\"hosts_found\""));
}

#[tokio::test]
async fn scenario_run_queue_spawns_jobs() {
    let state = test_state().await;

    let mut j1 = Job::new("discovery".into());
    j1.id = "jobA".into();
    j1.priority = JobPriority::CRITICAL;
    j1.config = serde_json::json!({"target": "127.0.0.1/32"});

    let mut j2 = Job::new("discovery".into());
    j2.id = "jobB".into();
    j2.priority = JobPriority::LOW;
    j2.config = serde_json::json!({"target": "127.0.0.1/32"});

    repository::create_job(&state.db, &j1).await.unwrap();
    repository::create_job(&state.db, &j2).await.unwrap();

    JobExecutor::run_queue(&state).await;

    // Give spawned tasks time to complete
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let a = repository::get_job(&state.db, "jobA").await.unwrap().unwrap();
    let b = repository::get_job(&state.db, "jobB").await.unwrap().unwrap();

    assert_eq!(a.status, "completed");
    assert_eq!(b.status, "completed");
}

#[tokio::test]
async fn scenario_resume_incomplete_jobs_requeues_and_runs() {
    let state = test_state().await;

    let mut job = Job::new("discovery".into());
    job.id = "jobR".into();
    job.status = "running".into(); // leftover unfinished
    job.config = serde_json::json!({"target": "127.0.0.1/32"});

    repository::create_job(&state.db, &job).await.unwrap();

    JobExecutor::resume_incomplete_jobs(state.clone()).await;

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let updated = repository::get_job(&state.db, "jobR").await.unwrap().unwrap();

    assert_eq!(updated.status, "completed");
    assert!(updated.results.is_some());
}
