use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use crate::state::AppState;
use crate::db::repository;

/// List all discovered hosts
pub async fn list_hosts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match repository::list_hosts(&state.db).await {
        Ok(hosts) => Json(hosts).into_response(),
        Err(e) => {
            tracing::error!("Failed to list hosts: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to list hosts"})),
            ).into_response()
        }
    }
}

/// Get details for a specific host by IP
pub async fn get_host(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    match repository::get_host(&state.db, &ip).await {
        Ok(Some(host)) => (axum::http::StatusCode::OK, Json(host)).into_response(),
        Ok(None) => (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Host with IP {} not found", ip)})),
        ).into_response(),
        Err(e) => {
            tracing::error!("Failed to get host: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to get host"})),
            ).into_response()
        }
    }
}