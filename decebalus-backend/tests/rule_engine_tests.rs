// Integration test: facts persisted in the DB flow through the rule engine and
// become ranked findings via Orchestrator::run_rule_engine (the war-table pass).

use std::sync::Arc;

use tokio::sync::{broadcast, Semaphore};

use decebalus_backend::db::repository;
use decebalus_backend::models::{Fact, Host, HostStatus, Port};
use decebalus_backend::services::Orchestrator;
use decebalus_backend::state::AppState;

async fn test_state() -> Arc<AppState> {
    let (tx, _rx) = broadcast::channel(64);
    let db_pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory DB");
    sqlx::migrate!("./migrations").run(&db_pool).await.expect("migrations");
    Arc::new(AppState { broadcaster: tx, db: db_pool, semaphore: Arc::new(Semaphore::new(5)) })
}

fn smb_host(ip: &str) -> Host {
    let mut h = Host::new(ip.to_string());
    h.status = HostStatus::Up;
    h.ports = vec![Port { number: 445, protocol: "tcp".into(), status: "open".into(), service: None, version: None, cpe: None }];
    h
}

#[tokio::test]
async fn rule_engine_persists_ranked_findings_from_facts() {
    let state = test_state().await;

    // A host with open SMB and signing disabled → should yield a relay finding.
    repository::upsert_host(&state.db, &smb_host("10.0.0.20")).await.unwrap();
    repository::upsert_fact(
        &state.db,
        &Fact::new("host", "10.0.0.20", "smb_signing", serde_json::json!(false)),
    )
    .await
    .unwrap();

    let count = Orchestrator::run_rule_engine(&state).await;
    assert!(count > 0, "engine should produce findings");

    let findings = repository::list_findings(&state.db, "").await.unwrap();

    // The relay finding exists with the expected value score.
    let relay = findings.iter().find(|f| f.dedup_key == "relay:10.0.0.20").expect("relay finding");
    assert_eq!(relay.value_score, 66);
    assert_eq!(relay.job_type.as_deref(), Some("ad-relay-recon"));

    // Findings are returned ranked by value (highest first).
    assert!(
        findings.windows(2).all(|w| w[0].value_score >= w[1].value_score),
        "findings must be ranked by value_score"
    );
}

#[tokio::test]
async fn rule_engine_is_idempotent_across_passes() {
    let state = test_state().await;
    repository::upsert_host(&state.db, &smb_host("10.0.0.30")).await.unwrap();

    Orchestrator::run_rule_engine(&state).await;
    let first = repository::list_findings(&state.db, "").await.unwrap().len();
    Orchestrator::run_rule_engine(&state).await;
    let second = repository::list_findings(&state.db, "").await.unwrap().len();

    assert_eq!(first, second, "re-running the engine must not duplicate findings");
}
