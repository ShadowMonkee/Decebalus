use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::db::repository;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct HistoryQuery {
    limit: Option<i64>,
}

/// List recent host change-events (newest first).
/// GET /api/history?limit=100
pub async fn list_history(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HistoryQuery>,
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    match repository::list_host_events(&state.db, limit).await {
        Ok(events) => Json(events).into_response(),
        Err(e) => {
            tracing::error!("Failed to list history: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to list history" })),
            )
                .into_response()
        }
    }
}
