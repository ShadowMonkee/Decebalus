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
/// Returns the config object directly, i.e. `{ "settings": { ... } }`.
pub async fn get_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
   match repository::get_config(&state.db).await {
        // Serialize the Config as-is → `{ "settings": { ... } }` so the frontend
        // can read `response.settings` directly (no envelope wrapping).
        Ok(config) => Json(config).into_response(),

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
/// Body: { "settings": { "key": "value", ... } }
/// A bare settings object (without the `settings` wrapper) is also accepted.
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

    // Unwrap the `settings` envelope if present; otherwise treat the whole body
    // as the settings object. This prevents the previous double-wrapping bug.
    config.settings = payload
        .get("settings")
        .cloned()
        .unwrap_or(payload);

    if let Err(e) = repository::update_config(&state.db, &config).await {
        tracing::error!("Failed to update config: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": e.to_string() })),
        ).into_response();
    }

    // Refresh the live settings snapshot so changes take effect without a restart,
    // and apply the (possibly new) log level immediately.
    crate::settings::reload(&state.db).await;
    crate::settings::set_log_level(&crate::settings::current().log_level);

    Json(json!({ "status": "success", "message": "Configuration updated successfully" })).into_response()
}