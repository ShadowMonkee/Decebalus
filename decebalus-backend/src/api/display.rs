use axum::{
    extract::State,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use crate::AppState;

/// Get e-paper display status
/// GET /api/display/status
pub async fn get_display_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let status = state.display_status.lock().await;
    Json(status.clone())
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
    
    let mut display_status = state.display_status.lock().await;
    display_status.update("updated".to_string());
    
    let _ = state.broadcaster.send(format!("display_updated:{}", text));
    
    Json(serde_json::json!({
        "message": format!("Updating e-paper display with: {}", text),
        "status": "success"
    }))
}