use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::db::repository;
use crate::models::{Credential, Engagement};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateEngagementRequest {
    pub name: String,
    pub scope_cidrs: Option<Vec<String>>,
    pub domain: Option<String>,
    pub dc_ip: Option<String>,
    // Optional starting credential ("assumed breach" foothold).
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Create an engagement (scope + optional AD context + optional starting cred),
/// and make it the active engagement.
/// POST /api/engagements
pub async fn create_engagement(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateEngagementRequest>,
) -> impl IntoResponse {
    if payload.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "name is required" }))).into_response();
    }

    let scope_cidrs = payload.scope_cidrs.unwrap_or_default();
    for c in &scope_cidrs {
        if c.parse::<IpNet>().is_err() {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("invalid CIDR: {}", c) }))).into_response();
        }
    }

    let mut e = Engagement::new(payload.name.trim().to_string());
    e.scope_cidrs = scope_cidrs;
    e.domain = payload.domain.clone();
    e.dc_ip = payload.dc_ip.clone();

    if let Err(err) = repository::create_engagement(&state.db, &e).await {
        tracing::error!("create_engagement failed: {}", err);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to create engagement" }))).into_response();
    }
    let _ = repository::set_active_engagement(&state.db, &e.id).await;

    // Store the starting credential, if one was supplied.
    if let (Some(user), Some(pass)) = (payload.username.as_ref(), payload.password.as_ref()) {
        if !user.is_empty() {
            let mut c = Credential::new(user.clone(), pass.clone());
            c.engagement_id = e.id.clone();
            c.domain = payload.domain.clone().unwrap_or_default();
            let _ = repository::add_credential(&state.db, &c).await;
        }
    }

    let _ = state.broadcaster.send(format!("engagement_active:{}", e.id));
    (StatusCode::CREATED, Json(e)).into_response()
}

/// List all engagements, newest first.
/// GET /api/engagements
pub async fn list_engagements(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match repository::list_engagements(&state.db).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => {
            tracing::error!("list_engagements failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to list engagements" }))).into_response()
        }
    }
}

/// Get the active engagement (or null).
/// GET /api/engagements/active
pub async fn active_engagement(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match repository::get_active_engagement(&state.db).await {
        Ok(e) => Json(e).into_response(),
        Err(e) => {
            tracing::error!("active_engagement failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to load active engagement" }))).into_response()
        }
    }
}

/// Make an engagement the active one.
/// POST /api/engagements/{id}/activate
pub async fn activate_engagement(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match repository::get_engagement(&state.db, &id).await {
        Ok(Some(_)) => {
            if let Err(e) = repository::set_active_engagement(&state.db, &id).await {
                tracing::error!("activate_engagement failed: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to activate" }))).into_response();
            }
            let _ = state.broadcaster.send(format!("engagement_active:{}", id));
            (StatusCode::OK, Json(json!({ "message": "activated" }))).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "engagement not found" }))).into_response(),
        Err(e) => {
            tracing::error!("activate lookup failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "lookup failed" }))).into_response()
        }
    }
}

/// List credentials for the active engagement (the credential vault).
/// GET /api/credentials
pub async fn list_credentials(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let eng = repository::get_active_engagement(&state.db)
        .await
        .ok()
        .flatten()
        .map(|e| e.id)
        .unwrap_or_default();
    match repository::list_credentials(&state.db, &eng).await {
        Ok(creds) => Json(creds).into_response(),
        Err(e) => {
            tracing::error!("list_credentials failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to list credentials" }))).into_response()
        }
    }
}
