use axum::{
    extract::State,
    response::IntoResponse,
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use serde_json::{json, Value};
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
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let mut config = match repository::get_config(&state.db).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to load config: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": e.to_string() })),
            ).into_response();
        }
    };

    config.settings = payload;

    if let Err(e) = repository::update_config(&state.db, &config).await {
        tracing::error!("Failed to update config: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": e.to_string() })),
        ).into_response();
    }

    Json(json!({ "status": "success", "message": "Configuration updated successfully" })).into_response()
}