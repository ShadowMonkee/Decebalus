use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use std::collections::HashMap;
use std::sync::Arc;
use serde_json::{json, Value};
use crate::models::{CveDetail, Host};
use crate::state::AppState;
use crate::db::repository;

/// Build a lookup of cached CVE details keyed by CVE ID.
async fn cve_lookup(state: &Arc<AppState>) -> HashMap<String, CveDetail> {
    repository::list_cve_details(&state.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|d| (d.cve_id.clone(), d))
        .collect()
}

/// Serialize a host to JSON, merging any cached CVE detail into each vulnerability
/// under a `detail` field. Vulnerabilities without a cached record get `detail: null`,
/// so the frontend can tell "not yet enriched" from "no CVSS data".
fn enrich_host(host: &Host, cves: &HashMap<String, CveDetail>) -> Value {
    let mut value = serde_json::to_value(host).unwrap_or_else(|_| json!({}));

    if let Some(vulns) = value
        .get_mut("vulnerabilities")
        .and_then(|v| v.as_array_mut())
    {
        for vuln in vulns.iter_mut() {
            let detail = vuln
                .get("id")
                .and_then(|id| id.as_str())
                .and_then(|id| cves.get(id));

            if let Some(obj) = vuln.as_object_mut() {
                let detail_value = detail
                    .map(|d| serde_json::to_value(d).unwrap_or(Value::Null))
                    .unwrap_or(Value::Null);
                obj.insert("detail".to_string(), detail_value);
            }
        }
    }

    value
}

/// List all discovered hosts, with each vulnerability enriched with cached CVE detail.
pub async fn list_hosts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match repository::list_hosts(&state.db).await {
        Ok(hosts) => {
            let cves = cve_lookup(&state).await;
            let enriched: Vec<Value> = hosts.iter().map(|h| enrich_host(h, &cves)).collect();
            Json(enriched).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to list hosts: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list hosts"})),
            ).into_response()
        }
    }
}

/// Get details for a specific host by IP, with vulnerabilities enriched with cached CVE detail.
pub async fn get_host(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    match repository::get_host(&state.db, &ip).await {
        Ok(Some(host)) => {
            let cves = cve_lookup(&state).await;
            (axum::http::StatusCode::OK, Json(enrich_host(&host, &cves))).into_response()
        }
        Ok(None) => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Host with IP {} not found", ip)})),
        ).into_response(),
        Err(e) => {
            tracing::error!("Failed to get host: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to get host"})),
            ).into_response()
        }
    }
}
