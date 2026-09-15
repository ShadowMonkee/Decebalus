// Integration tests exercising the repository + change-detection layer against a
// real (in-memory) SQLite database with the production migrations applied.

use decebalus_backend::db::repository;
use decebalus_backend::models::{Config, Host, HostStatus, Port, Vulnerability};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

async fn mem_pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory db");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations");
    pool
}

fn open_port(number: u16) -> Port {
    Port {
        number,
        protocol: "tcp".into(),
        status: "open".into(),
        service: None,
        version: None,
        cpe: None,
    }
}

#[tokio::test]
async fn config_round_trips_through_key_value_store() {
    let pool = mem_pool().await;
    let cfg = Config {
        settings: serde_json::json!({ "device_name": "pi-01", "max_scan_concurrency": 250 }),
    };
    repository::update_config(&pool, &cfg).await.unwrap();

    let got = repository::get_config(&pool).await.unwrap();
    assert_eq!(
        got.settings.get("device_name").and_then(|v| v.as_str()),
        Some("pi-01")
    );
    assert_eq!(
        got.settings.get("max_scan_concurrency").and_then(|v| v.as_u64()),
        Some(250)
    );
}

#[tokio::test]
async fn change_detection_records_expected_events() {
    let pool = mem_pool().await;

    // 1. Brand-new host → host_new
    let mut host = Host::new("10.0.0.5".into());
    host.status = HostStatus::Up;
    repository::upsert_host_tracked(&pool, &host).await.unwrap();

    // 2. A newly opened port → port_opened
    host.ports = vec![open_port(22)];
    repository::upsert_host_tracked(&pool, &host).await.unwrap();

    // 3. A newly detected vulnerability → vuln_new
    host.vulnerabilities = vec![Vulnerability {
        id: "CVE-2024-0001".into(),
        description: "x".into(),
        severity: "HIGH".into(),
    }];
    repository::upsert_host_tracked(&pool, &host).await.unwrap();

    // 4. Host goes down → host_down
    host.status = HostStatus::Down;
    repository::upsert_host_tracked(&pool, &host).await.unwrap();

    let events = repository::list_host_events(&pool, 50).await.unwrap();
    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert!(types.contains(&"host_new"), "events: {types:?}");
    assert!(types.contains(&"port_opened"), "events: {types:?}");
    assert!(types.contains(&"vuln_new"), "events: {types:?}");
    assert!(types.contains(&"host_down"), "events: {types:?}");

    // vuln_new carries the CVE id and severity.
    let vuln = events.iter().find(|e| e.event_type == "vuln_new").unwrap();
    assert_eq!(vuln.detail.as_deref(), Some("CVE-2024-0001"));
    assert_eq!(vuln.severity.as_deref(), Some("HIGH"));
}

#[tokio::test]
async fn re_upserting_unchanged_host_produces_no_duplicate_events() {
    let pool = mem_pool().await;

    let mut host = Host::new("10.0.0.9".into());
    host.status = HostStatus::Up;
    host.ports = vec![open_port(80)];
    repository::upsert_host_tracked(&pool, &host).await.unwrap();

    let after_first = repository::list_host_events(&pool, 50).await.unwrap().len();

    // Same state again → no new events.
    repository::upsert_host_tracked(&pool, &host).await.unwrap();
    let after_second = repository::list_host_events(&pool, 50).await.unwrap().len();

    assert_eq!(after_first, after_second);
}

// ==================== ENGAGEMENT-MODEL FOUNDATIONS (Phase 1) ====================

use decebalus_backend::models::{Credential, Engagement, Fact, Finding};

#[tokio::test]
async fn engagement_create_get_and_active_selection() {
    let pool = mem_pool().await;

    let mut e = Engagement::new("Acme internal".into());
    e.scope_cidrs = vec!["10.0.0.0/24".into(), "10.0.1.0/24".into()];
    e.domain = Some("acme.local".into());
    repository::create_engagement(&pool, &e).await.unwrap();

    let got = repository::get_engagement(&pool, &e.id).await.unwrap().unwrap();
    assert_eq!(got.name, "Acme internal");
    assert_eq!(got.scope_cidrs, vec!["10.0.0.0/24", "10.0.1.0/24"]);
    assert_eq!(got.domain.as_deref(), Some("acme.local"));

    // It's the active engagement until archived.
    let active = repository::get_active_engagement(&pool).await.unwrap().unwrap();
    assert_eq!(active.id, e.id);

    repository::set_engagement_status(&pool, &e.id, "archived").await.unwrap();
    assert!(repository::get_active_engagement(&pool).await.unwrap().is_none());
    assert_eq!(repository::list_engagements(&pool).await.unwrap().len(), 1);
}

#[tokio::test]
async fn credential_upsert_upgrades_validation() {
    let pool = mem_pool().await;

    // Same identity added twice: unvalidated first, then proven valid.
    let mut c = Credential::new("svc_web".into(), "Summer2026!".into());
    c.domain = "acme.local".into();
    repository::add_credential(&pool, &c).await.unwrap();

    let mut c2 = c.clone();
    c2.id = uuid::Uuid::new_v4().to_string(); // different row id, same identity
    c2.validated = true;
    c2.valid_on = vec!["10.0.0.5:smb".into()];
    c2.privilege = "user".into();
    repository::add_credential(&pool, &c2).await.unwrap();

    let creds = repository::list_credentials(&pool, "").await.unwrap();
    assert_eq!(creds.len(), 1, "identical identity must dedup to one row");
    assert!(creds[0].validated);
    assert_eq!(creds[0].valid_on, vec!["10.0.0.5:smb"]);
    assert_eq!(creds[0].privilege, "user");
}

#[tokio::test]
async fn fact_upsert_dedups_and_latest_value_wins() {
    let pool = mem_pool().await;

    let f1 = Fact::new("host", "10.0.0.5", "smb_signing", serde_json::json!(true));
    repository::upsert_fact(&pool, &f1).await.unwrap();
    let f2 = Fact::new("host", "10.0.0.5", "smb_signing", serde_json::json!(false));
    repository::upsert_fact(&pool, &f2).await.unwrap();

    let facts = repository::get_facts_for_subject(&pool, "", "host", "10.0.0.5").await.unwrap();
    assert_eq!(facts.len(), 1, "same subject+key must dedup");
    assert_eq!(facts[0].value, serde_json::json!(false));
    assert_eq!(repository::list_facts(&pool, "").await.unwrap().len(), 1);
}

#[tokio::test]
async fn finding_upsert_dedups_and_respects_dismissed() {
    let pool = mem_pool().await;

    let mut f = Finding::new("adcs-esc1:10.0.0.10", "ADCS ESC1 on CA01");
    f.value_score = 80;
    f.severity = "critical".into();
    repository::upsert_finding(&pool, &f).await.unwrap();

    // Operator dismisses it.
    let listed = repository::list_findings(&pool, "").await.unwrap();
    assert_eq!(listed.len(), 1);
    repository::update_finding_status(&pool, &listed[0].id, "dismissed").await.unwrap();

    // A later rule-engine pass tries to re-raise the same finding — must NOT resurrect it.
    let mut f2 = Finding::new("adcs-esc1:10.0.0.10", "ADCS ESC1 on CA01");
    f2.value_score = 95;
    repository::upsert_finding(&pool, &f2).await.unwrap();

    let after = repository::list_findings(&pool, "").await.unwrap();
    assert_eq!(after.len(), 1, "dedup on (engagement, dedup_key)");
    assert_eq!(after[0].status, "dismissed", "dismissed findings stay dismissed");
    assert_eq!(after[0].value_score, 80, "no fields updated while dismissed");
}

#[tokio::test]
async fn claim_job_only_lets_one_worker_win() {
    use decebalus_backend::models::Job;
    let pool = mem_pool().await;

    let mut job = Job::new("discovery".into());
    job.id = "claim-1".into();
    repository::create_job(&pool, &job).await.unwrap();

    // First claim transitions queued -> running and wins.
    assert!(repository::claim_job(&pool, "claim-1").await.unwrap());
    // A second, overlapping run_queue pass finds it already running and loses,
    // so the same job can never be executed twice.
    assert!(!repository::claim_job(&pool, "claim-1").await.unwrap());

    let updated = repository::get_job(&pool, "claim-1").await.unwrap().unwrap();
    assert_eq!(updated.status, "running");
}

#[tokio::test]
async fn claim_job_refuses_cancelled_and_missing_jobs() {
    use decebalus_backend::models::Job;
    let pool = mem_pool().await;

    // A job cancelled between queueing and pickup must never be started.
    let mut job = Job::new("discovery".into());
    job.id = "claim-2".into();
    job.status = "cancelled".into();
    repository::create_job(&pool, &job).await.unwrap();
    assert!(!repository::claim_job(&pool, "claim-2").await.unwrap());

    // An unknown id claims nothing rather than erroring.
    assert!(!repository::claim_job(&pool, "does-not-exist").await.unwrap());
}
