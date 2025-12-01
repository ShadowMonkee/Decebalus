// tests/job_executor_tests.rs

use std::sync::Arc;
use std::collections::HashMap;

use tokio::sync::{broadcast, Semaphore};

use decebalus_backend::services::job_executor::JobExecutor;
use decebalus_backend::state::AppState;
use decebalus_backend::models::{Job, JobPriority};


mod repository {
    use decebalus_backend::models::{Config, Host};
    use super::*;
    use once_cell::sync::Lazy;
    use std::sync::Mutex;

    // thread-safe statics protected by Mutex
    static JOBS: Lazy<Mutex<Vec<Job>>> = Lazy::new(|| Mutex::new(Vec::new()));
    static LOGS: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

    pub async fn get_job(_db: &(), id: &str) -> Result<Option<Job>, String> {
        let jobs = JOBS.lock().map_err(|e| format!("lock error: {}", e))?;
        Ok(jobs.iter().cloned().find(|j| j.id == id))
    }

    pub async fn add_log(_db: &(), _sev: &str, _service: &str, _module: Option<&str>, _job_id: Option<&str>, content: &str) 
        -> Result<(), String> 
    {
        let mut logs = LOGS.lock().map_err(|e| format!("lock error: {}", e))?;
        logs.push(content.to_string());
        Ok(())
    }

    pub async fn update_job_status(_db: &(), id: &str, new_status: &str) -> Result<(), String> {
        let mut jobs = JOBS.lock().map_err(|e| format!("lock error: {}", e))?;
        for j in jobs.iter_mut() {
            if j.id == id {
                j.status = new_status.to_string();
            }
        }
        Ok(())
    }

    pub async fn update_job_results(_db: &(), id: &str, results: Option<String>) -> Result<(), String> {
        let mut jobs = JOBS.lock().map_err(|e| format!("lock error: {}", e))?;
        for j in jobs.iter_mut() {
            if j.id == id {
                j.results = results.clone();
            }
        }
        Ok(())
    }

    pub async fn insert_job(job: Job) {
        // This is fine to unwrap in test code, but map_err pattern above is more explicit
        let mut jobs = JOBS.lock().expect("failed to lock JOBS");
        jobs.push(job);
    }

    pub async fn get_queued_jobs(_db: &()) -> Result<Vec<Job>, String> {
        let jobs = JOBS.lock().map_err(|e| format!("lock error: {}", e))?;
        Ok(jobs
            .iter()
            .cloned()
            .filter(|j| j.status == "queued")
            .collect())
    }

    pub async fn get_running_jobs(_db: &()) -> Result<Vec<Job>, String> {
        let jobs = JOBS.lock().map_err(|e| format!("lock error: {}", e))?;
        Ok(jobs
            .iter()
            .cloned()
            .filter(|j| j.status == "running")
            .collect())
    }

    pub async fn list_hosts(_db: &()) -> Result<Vec<Host>, String> {
        Ok(vec![])  // not needed for this test set
    }

    pub async fn get_config(_db: &()) -> Result<Config, String> {
        Err("not used in tests".into())
    }
}

mod scanner {
    use super::*;

    pub struct NetworkScanner;

    impl NetworkScanner {
        pub async fn discover_hosts(_target: &str, _state: &Arc<AppState>) -> Result<Vec<String>, String> {
            Ok(vec!["192.168.0.10".to_string(), "192.168.0.11".to_string()])
        }
    }
}

mod port_scanner {
    use super::*;

    pub struct PortScanner;

    impl PortScanner {
        pub async fn scan_host(_ip: &str, _state: &Arc<AppState>) -> Result<u32, String> {
            Ok(5) // pretend we found 5 ports
        }
    }
}

fn test_state() -> Arc<AppState> {
    // Broadcast channel for tests
    let (tx, _rx) = broadcast::channel(32);

    // In-memory SQLite database
    let db_pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(5)
        .connect_lazy("sqlite::memory:")
        .expect("failed to create mock pool");

    // Manual AppState (do NOT use AppState::new here)
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
    let state = test_state();

    let job = Job {id:"job1".into(),created_at:"now".into(),job_type:"discovery".into(),priority:JobPriority::NORMAL,status:"queued".into(),results:None, scheduled_at: None };

    // Insert into mock DB
    repository::insert_job(job.clone()).await;

    // Run the executor
    let permit = state.semaphore.clone().acquire_owned().await.unwrap();
    JobExecutor::execute_job(job.clone(), state.clone(), permit).await;

    // Retrieve updated job
    let updated = repository::get_job(&(), "job1").await.unwrap().unwrap();

    assert_eq!(updated.status, "completed");
    assert!(updated.results.is_some());
    assert!(updated.results.as_ref().unwrap().contains("\"hosts_found\""));
}

#[tokio::test]
async fn scenario_run_queue_spawns_jobs() {
    let state = test_state();

    let j1 = Job {
        id: "jobA".into(),
        created_at: "t".into(),
        job_type: "discovery".into(),
        priority: JobPriority::CRITICAL,
        status: "queued".into(),
        results: None,
        scheduled_at: None,
    };

    let j2 = Job {
        id: "jobB".into(),
        created_at: "t".into(),
        job_type: "discovery".into(),
        priority: JobPriority::LOW,
        status: "queued".into(),
        results: None,
        scheduled_at: None,
    };

    repository::insert_job(j1).await;
    repository::insert_job(j2).await;

    // Run the queue processor
    JobExecutor::run_queue(&state).await;

    // Give tasks time to run
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let a = repository::get_job(&(), "jobA").await.unwrap().unwrap();
    let b = repository::get_job(&(), "jobB").await.unwrap().unwrap();

    assert_eq!(a.status, "completed"); // CRITICAL should run first AND complete
    assert_eq!(b.status, "completed"); // lower priority but still gets run
}

#[tokio::test]
async fn scenario_resume_incomplete_jobs_requeues_and_runs() {
    let state = test_state();

    let job = Job {
        id: "jobR".into(),
        created_at: "t".into(),
        job_type: "discovery".into(),
        priority: JobPriority::NORMAL,
        status: "running".into(), // leftover unfinished
        results: None,
        scheduled_at: None,
    };

    repository::insert_job(job.clone()).await;

    JobExecutor::resume_incomplete_jobs(state.clone()).await;

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let updated = repository::get_job(&(), "jobR").await.unwrap().unwrap();

    assert_eq!(updated.status, "completed");
    assert!(updated.results.is_some());
}
