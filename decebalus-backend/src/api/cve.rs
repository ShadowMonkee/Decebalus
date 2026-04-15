use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use std::sync::Arc;
use crate::db::repository;
use crate::models::{CveDetail, Job};
use crate::services::{CveEnrichment, JobExecutor};
use crate::state::AppState;

/// GET /api/cve — list all locally cached CVE records.
pub async fn list_cves(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match repository::list_cve_details(&state.db).await {
        Ok(details) => Json(details).into_response(),
        Err(e) => {
            tracing::error!("Failed to list CVE details: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "DB error"}))).into_response()
        }
    }
}

/// GET /api/cve/{id} — get (or fetch-and-cache) enriched detail for one CVE.
pub async fn get_cve(
    State(state): State<Arc<AppState>>,
    Path(cve_id): Path<String>,
) -> impl IntoResponse {
    // Basic sanity check — CVE IDs are of the form CVE-YYYY-NNNNN
    if !cve_id.starts_with("CVE-") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid CVE ID format"})),
        )
            .into_response();
    }

    match CveEnrichment::get(&state.db, &cve_id).await {
        Some(detail) => Json::<CveDetail>(detail).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("{} not found in NVD", cve_id)})),
        )
            .into_response(),
    }
}

/// POST /api/cve/sync — create a `cve-sync` job and queue it via the normal
/// job executor.  Returns the created Job so the caller can track progress.
pub async fn sync_cves(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let job = Job::new("cve-sync".to_string());

    if let Err(e) = repository::create_job(&state.db, &job).await {
        tracing::error!("Failed to create cve-sync job: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create job"})),
        )
            .into_response();
    }

    let _ = state.broadcaster.send(format!("job_queued:{}:cve-sync", job.id));

    let state_clone = state.clone();
    tokio::spawn(async move {
        JobExecutor::run_queue(&state_clone).await;
    });

    (StatusCode::CREATED, Json(job)).into_response()
}
