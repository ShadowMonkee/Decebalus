//! Optional bearer-token auth. Off by default so the local web UI works with no
//! setup. When `DECEBALUS_TOKEN` is set (headless/remote/CLI hardening — the
//! server now holds credentials and loot), every request must present
//! `Authorization: Bearer <token>`. The TUI reads the same env var.

use axum::{
    body::Body,
    extract::Request,
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

pub async fn require_token(req: Request<Body>, next: Next) -> Response {
    if let Ok(token) = std::env::var("DECEBALUS_TOKEN") {
        if !token.is_empty() {
            let presented = req
                .headers()
                .get(AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.strip_prefix("Bearer "));
            if presented != Some(token.as_str()) {
                return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response();
            }
        }
    }
    next.run(req).await
}
