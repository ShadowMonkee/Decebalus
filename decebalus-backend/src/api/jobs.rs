use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use crate::models::Job;
use crate::AppState;
use crate::services::JobExecutor;
use crate::db::repository;

/// Create a new job
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
    
    // Save to database
    if let Err(e) = repository::create_job(&state.db, &job).await {
        tracing::error!("Failed to create job in database: {}", e);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to create job"})),
        ).into_response();
    }

    let _ = state
        .broadcaster
        .send(format!("job_queued:{}:{}", job.id, job_type));

    // Spawn job execution in background
    let state_clone = state.clone();
    tokio::spawn(async move {
        JobExecutor::run_queue(&state_clone).await;
    });

    (axum::http::StatusCode::CREATED, Json(job)).into_response()
}

/// List all jobs
pub async fn list_jobs(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match repository::list_jobs(&state.db).await {
        Ok(jobs) => Json(jobs).into_response(),
        Err(e) => {
            tracing::error!("Failed to list jobs: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to list jobs"})),
            ).into_response()
        }
    }
}

/// Get a specific job by ID
pub async fn get_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match repository::get_job(&state.db, &id).await {
        Ok(Some(job)) => (axum::http::StatusCode::OK, Json(job)).into_response(),
        Ok(None) => (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Job with ID {} not found", id)})),
        ).into_response(),
        Err(e) => {
            tracing::error!("Failed to get job: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to get job"})),
            ).into_response()
        }
    }
}

/// Cancel a running job
pub async fn cancel_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match repository::update_job_status(&state.db, &id, "cancelled").await {
        Ok(_) => {
            let _ = state.broadcaster.send(format!("job_cancelled:{}", id));
            (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({
                    "message": format!("Cancelling job with {} ID", id)
                })),
            ).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to cancel job: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to cancel job"})),
            ).into_response()
        }
    }
}