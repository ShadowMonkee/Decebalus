use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use crate::AppState;
use crate::db::repository;

pub async fn get_all_logs(state: State<Arc<AppState>>) -> impl IntoResponse {
    match repository::get_logs(&state.db).await {
        Ok(logs) => Json(logs).into_response(),
        Err(e) => {
            tracing::error!("Failed to list logs: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to list logs"})),
            ).into_response()
        }
    }
}

pub async fn get_logs_by_job_id(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {

    match repository::get_logs_by_job_id(&state.db, job_id).await {
        Ok(logs) => Json(logs).into_response(),
        Err(e) => {
            tracing::error!("Failed to get logs for job: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Failed to retrieve logs" })),
            )
            .into_response()
        }
    }
}
