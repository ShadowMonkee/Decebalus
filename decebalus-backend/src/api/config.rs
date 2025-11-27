use axum::{
    extract::State,
    response::IntoResponse,
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use serde_json::json;
use crate::state::AppState;
use crate::db::repository;


/// Get current configuration
/// GET /api/config
pub async fn get_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
   match repository::get_config(&state.db).await {
        Ok(config) => Json(json!({
            "status": "success",
            "config": config
        })).into_response(),

        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "message": e.to_string()
            }))
        ).into_response(),
    }
}

/// Update configuration
/// POST /api/config
/// Body: { "key": "value", ... } (any JSON object)
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Ok(mut config) = repository::get_config(&state.db).await {
        config.settings = payload;

        if let Err(e) = repository::update_config(&state.db, &config).await {
            tracing::error!("Failed to update config: {}", e);
        }
    
        Json(serde_json::json!({
            "message": "Configuration updated successfully",
            "status": "success"
        }))
    } else {
        Json(serde_json::json!({
            "message": "Configuration updated failed",
            "status": "failed"
        }))
    }
}