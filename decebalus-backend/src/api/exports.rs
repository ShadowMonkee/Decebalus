use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;
use crate::state::AppState;

fn export_dir() -> String {
    std::env::var("EXPORT_DIR").unwrap_or_else(|_| "data/exports".to_string())
}

/// GET /api/exports — list all export files, newest first.
pub async fn list_exports(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    let dir = export_dir();

    let mut read_dir = match tokio::fs::read_dir(&dir).await {
        Ok(d) => d,
        Err(_) => {
            // Directory doesn't exist yet — no exports have been run.
            return Json(json!([])).into_response();
        }
    };

    let mut files: Vec<serde_json::Value> = Vec::new();

    while let Ok(Some(entry)) = read_dir.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        if let Ok(meta) = entry.metadata().await {
            let size = meta.len();
            let modified_unix = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());

            files.push(json!({
                "filename":    name,
                "size":        size,
                "modified_at": modified_unix,
            }));
        }
    }

    // Newest first (filenames are timestamped so lexicographic sort works).
    files.sort_by(|a, b| {
        let a = a["filename"].as_str().unwrap_or("");
        let b = b["filename"].as_str().unwrap_or("");
        b.cmp(a)
    });

    Json(json!(files)).into_response()
}

/// GET /api/exports/{filename} — download a single export file.
pub async fn download_export(
    State(_state): State<Arc<AppState>>,
    Path(filename): Path<String>,
) -> Response {
    // Security: reject anything that could escape the exports directory.
    if filename.contains('/') || filename.contains('\\') || filename.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid filename" })),
        )
            .into_response();
    }
    if !filename.ends_with(".json") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Only .json files are available for download" })),
        )
            .into_response();
    }

    let file_path = format!("{}/{}", export_dir(), filename);

    match tokio::fs::read(&file_path).await {
        Ok(bytes) => {
            let disposition = format!("attachment; filename=\"{}\"", filename);
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_DISPOSITION, disposition)
                .header(header::CONTENT_LENGTH, bytes.len())
                .body(axum::body::Body::from(bytes))
                .unwrap()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Export file not found" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to read export file '{}': {}", file_path, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to read export file" })),
            )
                .into_response()
        }
    }
}
