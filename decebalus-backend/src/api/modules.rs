use axum::{response::IntoResponse, Json};
use crate::services::attacks;

/// List all available attack/exploit modules and their metadata.
/// GET /api/modules
pub async fn list_modules() -> impl IntoResponse {
    Json(attacks::all_meta())
}
