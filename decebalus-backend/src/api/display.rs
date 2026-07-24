use axum::{
    extract::State,
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use std::sync::Arc;
use serde_json::{json, Value};
use crate::models::DisplayStatus;
use crate::state::AppState;
use crate::db::repository;

/// Get e-paper display status
/// GET /api/display/status
pub async fn get_display_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match repository::get_display_status(&state.db).await {
        Ok(status) => Json(status).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Failed to get display status: {}", e) })),
        ).into_response(),
    }
}

/// Update e-paper display
/// POST /api/display/update
/// Body: { "text": "Status message", "image": "optional_base64_image" }
pub async fn update_display(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<Value>,
) -> Response {
    let text = payload
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("No text provided");

    // Create a new DisplayStatus instance
    let new_status = DisplayStatus {
        status: text.to_string(),
        last_update: Utc::now().to_rfc3339(),
    };

    if let Err(e) = repository::update_display_status(&state.db, &new_status).await {
        tracing::error!("Failed to update display status: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to update display status" })),
        ).into_response();
    }

    let _ = state.broadcaster.send(format!("display_updated:{}", text));

    Json(json!({ "status": "success", "message": format!("Display updated: {}", text) })).into_response()
}

