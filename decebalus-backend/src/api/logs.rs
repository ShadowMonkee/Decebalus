use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use crate::AppState;
use crate::db::repository;

pub async fn get_all_logs(state: State<Arc<AppState>>) -> impl IntoResponse {
    match repository::get_logs(&state.db).await {
        Ok(logs) => Json(logs).into_response(),
        Err(e) => {
            tracing::error!("Failed to list logs: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to list logs"})),
            ).into_response()
        }
    }
}

pub async fn get_log(state: State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    println!("Get Log: {}", &id);
    match repository::get_log(&state.db, id).await {
        Ok(logs) => Json(logs).into_response(),
        Err(e) => {
            tracing::error!("Failed to list logs: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to list logs"})),
            ).into_response()
        }
    }
}