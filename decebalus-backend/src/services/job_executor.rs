use std::sync::Arc;
use crate::models::Job;
use crate::AppState;
use crate::services::{scanner, port_scanner};
use crate::db::repository;


/// Job Executor Service
/// Responsible for executing jobs based on their type
pub struct JobExecutor;

impl JobExecutor {
    /// Execute a job based on its type
    /// This runs in a separate tokio task (background worker)
    pub async fn execute_job(job: Job, state: Arc<AppState>) {
        tracing::info!("Starting job execution: {} (type: {})", job.id, job.job_type);
        
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

}