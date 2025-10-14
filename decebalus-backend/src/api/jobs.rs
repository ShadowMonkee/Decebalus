use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use crate::models::Job;
use crate::AppState;
use crate::services::JobExecutor;

/// Create a new job
/// POST /api/jobs
/// Body: { "job_type": "discovery" | "port-scan" | "nmap-scan" | "export" }
pub async fn create_job(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let job_type = payload
        .get("job_type")
        .and_then(|v| v.as_str())
        .unwrap_or("discovery")
        .to_string();

    let job = Job::new(job_type.clone());

    {
        let mut jobs = state.jobs.lock().await;
        jobs.push(job.clone());
    }

    let _ = state
        .broadcaster
        .send(format!("job_queued:{}:{}", job.id, job_type));

    // ✨ NEW: Spawn job execution in background
    let state_clone = state.clone();
    let job_clone = job.clone();
    tokio::spawn(async move {
        JobExecutor::execute_job(job_clone, state_clone).await;
    });

    (axum::http::StatusCode::CREATED, Json(job))
}


/// List all jobs
/// GET /api/jobs
pub async fn list_jobs(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let jobs = state.jobs.lock().await;
    Json(jobs.clone())
}

/// Get a specific job by ID
/// GET /api/jobs/{id}
pub async fn get_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let jobs = state.jobs.lock().await;
    
    if let Some(job) = jobs.iter().find(|j| j.id == id) {
        (axum::http::StatusCode::OK, Json(job.clone())).into_response()
    } else {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Job with ID {} not found", id)})),
        )
            .into_response()
    }
}

/// Cancel a running job
/// POST /api/jobs/{id}/cancel
pub async fn cancel_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut jobs = state.jobs.lock().await;
    
    if let Some(job) = jobs.iter_mut().find(|j| j.id == id) {
        job.status = "cancelled".to_string();
        let _ = state.broadcaster.send(format!("job_cancelled:{}", id));
        
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "message": format!("Cancelling job with {} ID", id)
            })),
        )
    } else {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Job with ID {} not found", id)})),
        )
    }
}