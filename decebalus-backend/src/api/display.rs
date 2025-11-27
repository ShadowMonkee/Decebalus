use axum::{
    extract::State,
    response::IntoResponse,
    http::StatusCode,
    Json,
};
use chrono::Utc;
use std::sync::Arc;
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
            format!("Failed to get display status: {}", e),
        ).into_response(),
    }
}

/// Update e-paper display
/// POST /api/display/update
/// Body: { "text": "Status message", "image": "optional_base64_image" }
pub async fn update_display(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let text = payload
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("No text provided");

    // Create a new DisplayStatus instance
    let new_status = DisplayStatus {
        status: text.to_string(),
        last_update: Utc::now().to_rfc3339(),
    };

    // Save to DB through the repository
    if let Err(e) = repository::update_display_status(&state.db, &new_status).await {
        tracing::error!("Failed to update display status: {}", e);
    }

    // Broadcast update
    let _ = state.broadcaster.send(format!("display_updated:{}", text));

    // Return JSON response
    Json(serde_json::json!({
        "message": format!("Updating e-paper display with: {}", text),
        "status": "success"
    }))
}

