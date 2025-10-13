use axum::{
    extract::State,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use crate::AppState;

/// Get current configuration
/// GET /api/config
pub async fn get_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config.lock().await;
    Json(config.clone())
}

/// Update configuration
/// POST /api/config
/// Body: { "key": "value", ... } (any JSON object)
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut config = state.config.lock().await;
    config.settings = payload;
    
    Json(serde_json::json!({
        "message": "Configuration updated successfully",
        "status": "success"
    }))
}