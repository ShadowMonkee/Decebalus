use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::db::repository;
use crate::services::wordlists;
use crate::state::AppState;

/// List all wordlists (bundled SecLists + user-saved custom).
/// GET /api/wordlists
pub async fn list_wordlists(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match repository::list_wordlists(&state.db).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => {
            tracing::error!("list_wordlists failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to list wordlists" }))).into_response()
        }
    }
}

/// Lists larger than this are not returned for in-browser editing — a multi-million
/// line list would freeze the textarea. They stay usable by reference from the picker.
const MAX_EDITABLE_BYTES: i64 = 2 * 1024 * 1024; // 2 MB

/// Return a wordlist's raw content so the UI can load it into an editable textarea.
/// Refuses lists above the editable size cap. GET /api/wordlists/{id}/content
pub async fn get_wordlist_content(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wl = match repository::get_wordlist(&state.db, &id).await {
        Ok(Some(wl)) => wl,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({ "error": "Wordlist not found" }))).into_response();
        }
        Err(e) => {
            tracing::error!("get_wordlist_content failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to load wordlist" }))).into_response();
        }
    };

    if wl.size_bytes > MAX_EDITABLE_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({
                "error": format!(
                    "\"{}\" has {} entries — too large to open in the editor. Select it from the picker to use it as-is.",
                    wl.name, wl.entry_count
                ),
                "entry_count": wl.entry_count,
                "size_bytes": wl.size_bytes,
            })),
        ).into_response();
    }

    match tokio::fs::read_to_string(&wl.file_path).await {
        Ok(content) => Json(json!({
            "id": wl.id,
            "name": wl.name,
            "category": wl.category,
            "entry_count": wl.entry_count,
            "content": content,
        })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Failed to read list file: {e}") })),
        ).into_response(),
    }
}

#[derive(Deserialize)]
pub struct SaveCustomRequest {
    pub name: String,
    pub category: String,
    pub content: String,
}

/// Save a pasted list under a name so it can be reselected later.
/// POST /api/wordlists/custom
pub async fn save_custom_wordlist(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SaveCustomRequest>,
) -> impl IntoResponse {
    match wordlists::save_custom(&state.db, &payload.name, &payload.category, &payload.content).await {
        Ok(wl) => (StatusCode::CREATED, Json(wl)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

/// Delete a custom wordlist. Bundled entries are refused (re-seeded on boot).
/// DELETE /api/wordlists/{id}
pub async fn delete_wordlist(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match wordlists::delete(&state.db, &id).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "message": "deleted" }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}
