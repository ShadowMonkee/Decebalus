use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use std::sync::Arc;
use axum::http::StatusCode;
use axum::response::Response;
use ipnet::IpNet;
use serde_json::{json, Map, Value};
use crate::models::{CreateJobRequest, Job};
use crate::state::AppState;
use crate::services::JobExecutor;
use crate::db::{repository, DbPool};

/// Create a new job
pub async fn create_job(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateJobRequest>,
) -> impl IntoResponse {

    let mut job = match parse_job_from_request(&payload) {
        Ok(job) => job,
        Err(resp) => return resp
    };

    // Save to database
    if let Err(e) = repository::create_job(&state.db, &job).await {
        tracing::error!("Failed to create job in database: {}", e);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create job"})),
        ).into_response();
    }

    let _ = state
        .broadcaster
        .send(format!("job_queued:{}:{}", job.id, job.job_type));

    // Spawn job execution in background
    let state_clone = state.clone();
    tokio::spawn(async move {
        JobExecutor::run_queue(&state_clone).await;
    });

    (axum::http::StatusCode::CREATED, Json(job)).into_response()
}

pub async fn schedule_job(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateJobRequest>,
) -> impl IntoResponse {

    let mut job = match parse_job_from_request(&payload) {
        Ok(job) => job,
        Err(resp) => return resp
    };
    job.status = "scheduled".to_string();

    if let Err(resp) = persist_job(&state.db, &job).await {
        return resp;
    }

    let _ = state
        .broadcaster
        .send(format!("job_scheduled:{}:{}:{}", job.id, job.job_type, job.scheduled_at.unwrap_or(0)));
    tracing::info!("job_scheduled:{}:{}:{}", job.id, job.job_type, job.scheduled_at.unwrap_or(0));

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
                Json(json!({"error": "Failed to list jobs"})),
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
            Json(json!({"error": format!("Job with ID {} not found", id)})),
        ).into_response(),
        Err(e) => {
            tracing::error!("Failed to get job: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to get job"})),
            ).into_response()
        }
    }
}

/// Cancel a running job
pub async fn cancel_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {

    let job = match repository::get_job(&state.db, &id).await {
        Ok(Some(job)) => job,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": format!("Job with ID {} not found", id) })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Failed to get job: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to get job" })),
            )
                .into_response();
        }
    };

    if !job.is_queued() && !job.is_running() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Job cannot be cancelled" })),
        )
            .into_response();
    }

    if let Err(e) = repository::update_job_status(&state.db, &id, "cancelled").await {
        tracing::error!("Failed to cancel job: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to cancel job" })),
        )
            .into_response();
    }

    let _ = state.broadcaster.send(format!("job_cancelled:{}", id));

    (
        StatusCode::OK,
        Json(json!({
            "message": format!("Cancelling job with {} ID", id)
        })),
    )
        .into_response()
}

fn parse_job_from_request(payload: &CreateJobRequest) -> Result<Job, Response>  {
    let job_type = payload.job_type.clone();
    let mut job = Job::new(job_type.clone());

    let mut config = Map::new();

    if job_type == "discovery" {
        let target = payload.target.clone().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "target is required for discovery jobs"
                })),
            )
                .into_response()
        })?;

        validate_cidr(&target).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e })),
            )
                .into_response()
        })?;

        config.insert("target".to_string(), Value::String(target));
    }

    if !payload.scheduled_at.is_none() {
        job.scheduled_at = Some(payload.scheduled_at.unwrap_or(Utc::now().timestamp()));
    }

    job.config = Value::Object(config);
    Ok(job)
}

async fn persist_job(
    db: &DbPool,
    job: &Job,
) -> Result<(), Response> {
    if let Err(e) = repository::create_job(db, job).await {
        tracing::error!("Failed to create job in database: {}", e);

        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "Failed to create job"
            })),
        ).into_response());
    }

    Ok(())
}


fn validate_cidr(cidr: &str) -> Result<IpNet, String> {
    cidr.parse::<IpNet>()
        .map_err(|_| format!("Invalid CIDR notation: {}", cidr))
}