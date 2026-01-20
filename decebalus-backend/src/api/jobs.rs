use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use std::sync::Arc;
use axum::http::StatusCode;
use ipnet::IpNet;
use serde_json::{Map, Value};
use crate::models::{CreateJobRequest, Job};
use crate::state::AppState;
use crate::services::JobExecutor;
use crate::db::repository;

/// Create a new job
pub async fn create_job(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateJobRequest>,
) -> impl IntoResponse {

    let job_type = payload.job_type.clone();
    let mut job = Job::new(job_type.clone());

    let mut config = Map::new();

    if job_type == "discovery" {
        let target = match payload.target.clone() {
            Some(t) => t,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "target is required for discovery jobs"})),
                ).into_response();
            }
        };

        if let Err(e) = validate_cidr(&target) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            ).into_response();
        }

        config.insert("target".to_string(), serde_json::Value::String(target));
    }
    job.config = Value::Object(config);

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

pub async fn schedule_job(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let job_type = payload
        .get("job_type")
        .and_then(|v| v.as_str())
        .unwrap_or("discovery")
        .to_string();
    let scheduled_at = payload
        .get("scheduled_at")
        .and_then(|v| v.as_i64())
        .unwrap_or(Utc::now().timestamp());

    let mut job = Job::new(job_type.clone());
    job.scheduled_at = Some(scheduled_at);
    job.status = "scheduled".to_string();

    if let Err(e) = repository::create_job(&state.db, &job).await {
        tracing::error!("Failed to create job in database: {}", e);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to create job"})),
        ).into_response();
    }

    let scheduled_at = job.scheduled_at.clone().unwrap_or_else(|| Utc::now().timestamp());
    let _ = state
        .broadcaster
        .send(format!("job_scheduled:{}:{}:{}", job.id, job_type, scheduled_at));
    tracing::info!("job_scheduled:{}:{}:{}", job.id, job_type, scheduled_at);

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

fn validate_cidr(cidr: &str) -> Result<IpNet, String> {
    cidr.parse::<IpNet>()
        .map_err(|_| format!("Invalid CIDR notation: {}", cidr))
}