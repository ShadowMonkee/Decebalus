use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use crate::AppState;

/// List all discovered hosts
/// GET /api/hosts
pub async fn list_hosts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let hosts = state.hosts.lock().await;
    Json(hosts.clone())
}

/// Get details for a specific host by IP
/// GET /api/hosts/{ip}
pub async fn get_host(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    let hosts = state.hosts.lock().await;
    
    if let Some(host) = hosts.iter().find(|h| h.ip == ip) {
        (axum::http::StatusCode::OK, Json(host.clone())).into_response()
    } else {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Host with IP {} not found", ip)})),
        )
            .into_response()
    }
}