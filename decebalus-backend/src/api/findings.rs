use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use std::sync::Arc;

use crate::db::repository;
use crate::models::{Job, JobPriority};
use crate::services::{JobExecutor, Orchestrator};
use crate::state::AppState;

/// The active engagement id, or "" (implicit global engagement).
async fn active_engagement_id(state: &Arc<AppState>) -> String {
    repository::get_active_engagement(&state.db)
        .await
        .ok()
        .flatten()
        .map(|e| e.id)
        .unwrap_or_default()
}

/// List findings for the active engagement, ranked by value.
/// GET /api/findings
pub async fn list_findings(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let eng = active_engagement_id(&state).await;
    match repository::list_findings(&state.db, &eng).await {
        Ok(findings) => Json(findings).into_response(),
        Err(e) => {
            tracing::error!("Failed to list findings: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to list findings" }))).into_response()
        }
    }
}

/// Run a finding's prefilled job (one-click next-move).
/// POST /api/findings/{id}/run
pub async fn run_finding(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let finding = match repository::get_finding(&state.db, &id).await {
        Ok(Some(f)) => f,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({ "error": "finding not found" }))).into_response(),
        Err(e) => {
            tracing::error!("get_finding failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "lookup failed" }))).into_response();
        }
    };

    let Some(job_type) = finding.job_type.clone() else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "finding has no runnable job" }))).into_response();
    };

    let mut job = Job::new(job_type.clone());
    job.priority = JobPriority::HIGH; // operator-triggered → preempt background work
    job.config = finding.job_config.clone();

    if let Err(e) = repository::create_job(&state.db, &job).await {
        tracing::error!("Failed to create job for finding: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to create job" }))).into_response();
    }
    let _ = repository::update_finding_status(&state.db, &id, "running").await;
    let _ = state.broadcaster.send(format!("job_queued:{}:{}", job.id, job.job_type));

    let state_clone = state.clone();
    tokio::spawn(async move {
        JobExecutor::run_queue(&state_clone).await;
    });

    (StatusCode::CREATED, Json(job)).into_response()
}

/// Dismiss a finding so the rule engine won't re-raise it.
/// POST /api/findings/{id}/dismiss
pub async fn dismiss_finding(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match repository::update_finding_status(&state.db, &id, "dismissed").await {
        Ok(_) => {
            let _ = state.broadcaster.send(format!("finding_dismissed:{}", id));
            (StatusCode::OK, Json(json!({ "message": "dismissed" }))).into_response()
        }
        Err(e) => {
            tracing::error!("dismiss_finding failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to dismiss finding" }))).into_response()
        }
    }
}

/// Trigger a rule-engine pass on demand (re-evaluates and refreshes findings).
/// POST /api/engine/run
pub async fn run_engine(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let count = Orchestrator::run_rule_engine(&state).await;
    (StatusCode::OK, Json(json!({ "findings": count }))).into_response()
}
