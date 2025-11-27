use std::cmp::Ordering;
use std::sync::Arc;
use chrono::Utc;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{Duration, sleep};
use crate::models::{Job, JobPriority};
use crate::state::AppState;
use crate::services::{scanner, port_scanner};
use crate::db::repository;


/// Job Executor Service
/// Responsible for executing jobs based on their type
pub struct JobExecutor;
const THIS_SERVICE: &str = "job_executor";

impl JobExecutor {
    /// Execute a job based on its type
    /// This runs in a separate tokio task (background worker)
    pub async fn execute_job(job: Job, state: Arc<AppState>, _permit: OwnedSemaphorePermit) {
        tracing::info!("Starting job execution: {} (type: {})", &job.id, job.job_type);
        let _ = repository::add_log(&state.db, "INFO", "scanner", Some("job_executor"), Some(&job.id), "Starting job execution").await;
        let _ = state.broadcaster.send(format!("Starting job execution: {} (type: {})", &job.id, job.job_type));
        // Double-check that the job hasn't already been picked up
        match repository::get_job(&state.db, &job.id).await {
            Ok(Some(job)) => {
                if job.is_queued() || job.is_scheduled() {
                    // Update job status to running
                    Self::update_job_status(&state, &job.id, "running").await;
                    // Broadcast that job started
                    let _ = state.broadcaster.send(format!("job_running:{}", job.id));

                    // Execute based on job type
                    let result = match job.job_type.as_str() {
                        "discovery" => Self::run_discovery(&state, &job).await,
                        "port-scan" => Self::run_port_scan(&state, &job).await,
                        "nmap-scan" => Self::run_nmap_scan(&state, &job).await,
                        "export" => Self::run_export(&state, &job).await,
                        _ => {
                            tracing::warn!("Unknown job type: {}", job.job_type);
                            Err(format!("Unknown job type: {}", job.job_type))
                        }
                    };

                    // Update job with results
                    match result {
                        Ok(results) => {
                            Self::update_job_status(&state, &job.id, "completed").await;
                            Self::update_job_results(&state, &job.id, Some(results)).await;
                            let _ = state.broadcaster.send(format!("job_completed:{}", job.id));
                            tracing::info!("Job completed successfully: {}", job.id);
                        }
                        Err(error) => {
                            Self::update_job_status(&state, &job.id, "failed").await;
                            Self::update_job_results(&state, &job.id, Some(error.clone())).await;
                            let _ = state.broadcaster.send(format!("job_failed:{}:{}", job.id, error));
                            tracing::error!("Job failed: {} - {}", job.id, error);
                        }
                    }
                }
            }
            Ok(None) => (),
            Err(e) => {
                tracing::error!("Failed to get job: {}", e);
            }
        }

        // When `_permit` is dropped here, the semaphore slot is automatically released.
        tracing::debug!("Job finished, semaphore slot released: {}", job.id);
    }

    pub async fn run_queue(state: &Arc<AppState>) {
        let mut jobs = repository::get_queued_jobs(&state.db).await.unwrap_or_default();

        if jobs.is_empty() {
            return;
        }

        jobs.sort_by(|a, b| {
            use JobPriority::*;
            match (&a.priority, &b.priority) {
                (CRITICAL, LOW | NORMAL | HIGH) => Ordering::Less,
                (HIGH, CRITICAL) => Ordering::Greater,
                (NORMAL, CRITICAL) => Ordering::Greater,
                (LOW, CRITICAL) => Ordering::Greater,
                _ => Ordering::Equal,
            }
        });

        // Spawn jobs up to available permits
        for job in jobs {
            let state_clone = state.clone();
            let job_clone = job.clone();
            let semaphore = state.semaphore.clone();

            // Try to get a permit — if none available, skip or wait
            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    // No available slot; stop spawning
                    break;
                }
            };

            tokio::spawn(async move {
                // Run job with a semaphore permit.
                // Permit is dropped automatically at the end of the async block
                Self::execute_job(job_clone, state_clone, permit).await;
            });
        }
    }    
    /// Run network discovery
    async fn run_discovery(state: &Arc<AppState>, job: &Job) -> Result<String, String> {
        tracing::info!("Running network discovery for job {}", job.id);
        
        // Get target network from config (or use default)
        let target_network = {

            if let Ok(config) = repository::get_config(&state.db).await {
                config.settings
                .get("scan_config")
                .and_then(|c| c.get("target_network"))
                .and_then(|n| n.as_str())
                .unwrap_or("192.168.68.0/24")
                .to_string()
            } else {
                "192.168.68.0/24".to_string()
            }            
        };
        
        // Run network discovery
        let hosts_found = scanner::NetworkScanner::discover_hosts(&target_network, state).await?;
        
        let results = serde_json::json!({
            "job_id": job.id,
            "job_type": "discovery",
            "target_network": target_network,
            "hosts_found": hosts_found,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        
        Ok(results.to_string())
    }
    
    /// Run port scanning on discovered hosts
    async fn run_port_scan(state: &Arc<AppState>, job: &Job) -> Result<String, String> {
        tracing::info!("Running port scan for job {}", job.id);
        
        // Get all hosts to scan
        let hosts_to_scan = {
            let hosts = repository::list_hosts(&state.db)
            .await.map_err(|e| format!("Failed to list hosts: {}", e))?;
            hosts.iter().map(|h| h.ip.clone()).collect::<Vec<_>>()
        };
        
        if hosts_to_scan.is_empty() {
            return Err("No hosts available to scan. Run discovery first.".to_string());
        }
        
        let mut total_ports_found = 0;
        
        // Scan each host
        for ip in &hosts_to_scan {
            let open_ports = port_scanner::PortScanner::scan_host(ip, state).await?;
            total_ports_found += open_ports;
            
            // Broadcast progress
            let _ = state.broadcaster.send(format!(
                "scan_progress:{}:{}:{}",
                job.id, ip, open_ports
            ));
        }
        
        let results = serde_json::json!({
            "job_id": job.id,
            "job_type": "port-scan",
            "hosts_scanned": hosts_to_scan.len(),
            "total_ports_found": total_ports_found,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        
        Ok(results.to_string())
    }

        /// Resume any jobs that were marked as "running" when the app last shut down.
    /// These are treated as interrupted jobs and re-executed.
    pub async fn resume_incomplete_jobs(state: Arc<AppState>) {
        let content = "Checking for unfinished jobs after restart...";
        if let Err(e) = repository::add_log(&state.db, "INFO", THIS_SERVICE,None, None, content).await {
            tracing::warn!("Failed to persist log: {}", e);
        }
        tracing::info!("{}", content);

        // Step 1: fetch jobs that were left in 'running' state
        let running_jobs = match repository::get_running_jobs(&state.db).await {
            Ok(jobs) => jobs,
            Err(e) => {
                tracing::error!("Failed to load unfinished jobs: {}", e);
                return;
            }
        };

        if running_jobs.is_empty() {
            tracing::info!("No unfinished jobs found!");
            return;
        }

        tracing::info!("Found {} unfinished jobs. Resuming...", running_jobs.len());

        for job in running_jobs {
            let state_clone = state.clone();
            let job_clone = job.clone();
            let semaphore = state.semaphore.clone();

            // Step 2: acquire a permit before spawning
            match semaphore.clone().try_acquire_owned() {
                Ok(permit) => {
                    tokio::spawn(async move {
                        tracing::warn!(
                            "Resuming interrupted job: {} (type: {})",
                            job_clone.id,
                            job_clone.job_type
                        );
                        // Mark job back to 'queued' first to ensure clean re-run
                        if let Err(e) = repository::update_job_status(
                            &state_clone.db,
                            &job_clone.id,
                            "queued",
                        )
                        .await
                        {
                            tracing::error!(
                                "Failed to reset job {} to queued before resuming: {}",
                                job_clone.id,
                                e
                            );
                        }

                        // Re-run the job as usual
                        Self::execute_job(job_clone, state_clone, permit).await;
                    });
                }
                Err(_) => {
                    tracing::warn!(
                        "No available permits for resuming job {} — deferring until next run_queue()",
                        job.id
                    );
                    // Optional: mark them as queued again, so they'll get picked up later by run_queue()
                    if let Err(e) =
                        repository::update_job_status(&state.db, &job.id, "queued").await
                    {
                        tracing::error!(
                            "Failed to mark deferred resumed job {} as queued: {}",
                            job.id,
                            e
                        );
                    }
                }
            }
        }
    }
    
    /// Run full Nmap vulnerability scan
    async fn run_nmap_scan(state: &Arc<AppState>, job: &Job) -> Result<String, String> {
        tracing::info!("Running nmap scan for job {}", job.id);
        
        // TODO: Implement nmap integration
        // This would shell out to nmap command and parse results
        
        let results = serde_json::json!({
            "job_id": job.id,
            "job_type": "nmap-scan",
            "status": "not_implemented",
            "message": "Nmap scanning not yet implemented",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        
        Ok(results.to_string())
    }
    
    /// Export results to file
    async fn run_export(state: &Arc<AppState>, _job: &Job) -> Result<String, String> {
        tracing::info!("Running export");
        
        // Get all data
        let hosts = repository::list_hosts(&state.db).await
                .map_err(|e| format!("Failed to list hosts: {}", e))?;
        let jobs = repository::list_jobs(&state.db).await
                .map_err(|e| format!("Failed to list jobs: {}", e))?;
        
        let export_data = serde_json::json!({
            "export_date": chrono::Utc::now().to_rfc3339(),
            "jobs": jobs,
            "hosts": hosts,
        });
        
        // TODO: Write to file
        // std::fs::write("data/export.json", export_data.to_string())?;
        
        Ok(export_data.to_string())
    }
    
    async fn update_job_status(state: &Arc<AppState>, job_id: &str, status: &str) {
        if let Err(e) = repository::update_job_status(&state.db, job_id, status).await {
            tracing::error!("Failed to update job status: {}", e);
        }
    }

    async fn update_job_results(state: &Arc<AppState>, job_id: &str, results: Option<String>) {
        if let Err(e) = repository::update_job_results(&state.db, job_id, results).await {
            tracing::error!("Failed to update job results: {}", e);
        }
    }

    pub async fn check_and_run_scheduled_jobs(state: Arc<AppState>) {
        let check_interval = Duration::from_secs(30); // check every 60 seconds
        tracing::info!("Scheduler started...");

        loop {
            // Fetch jobs that are scheduled but not yet started and due for execution
            match repository::get_scheduled_jobs_due(&state.db, Utc::now()).await {
                Ok(jobs) if !jobs.is_empty() => {
                    tracing::info!("Found {} scheduled job(s) ready to run", jobs.len());

                    for job in jobs {
                        let state_clone = Arc::clone(&state);

                        // Acquire a semaphore permit before starting the job
                        let permit = match state_clone.semaphore.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::error!("Failed to acquire semaphore permit: {}", e);
                                continue;
                            }
                        };

                        // Spawn each job execution in the background
                        tokio::spawn(async move {
                            Self::execute_job(job, state_clone, permit).await;
                        });
                    }
                }
                Ok(_) => {
                    tracing::debug!("No scheduled jobs ready at this time");
                }
                Err(e) => {
                    tracing::error!("Error checking scheduled jobs: {}", e);
                }
            }

            // Wait before checking again
            sleep(check_interval).await;
        }
    }



}