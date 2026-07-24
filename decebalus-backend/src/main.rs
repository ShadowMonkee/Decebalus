mod api;
mod db;
mod models;
mod services;
mod settings;
mod state;

use axum::{
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, sync::Arc};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;

pub use state::AppState;

use crate::{db::repository, services::JobExecutor};

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    tracing::info!("Signal received, shutting down");
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    // Tracing with a reload handle so the Settings UI can change log level at runtime.
    let initial_level = std::env::var("RUST_LOG")
        .ok()
        .or_else(|| std::env::var("LOG_LEVEL").ok())
        .and_then(|s| s.parse::<LevelFilter>().ok())
        .unwrap_or(LevelFilter::INFO);
    let (level_filter, reload_handle) = tracing_subscriber::reload::Layer::new(initial_level);
    tracing_subscriber::registry()
        .with(level_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
    // Let settings::set_log_level swap the filter live without this file's tracing
    // types leaking into the settings module.
    settings::register_log_setter(Box::new(move |level: &str| {
        if let Ok(l) = level.parse::<LevelFilter>() {
            let _ = reload_handle.reload(l);
        }
    }));

    //Connect to DB
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:data/decebalus.db".to_string());

    std::fs::create_dir_all("data").expect("Failed to create data directory");

    let db_pool = db::init_pool(&database_url)
        .await
        .expect("Failed to initialize database");

    // Resolve runtime settings from the config table (env/defaults as fallback) and
    // apply the persisted log level.
    settings::init(settings::Settings::load(&db_pool).await);
    settings::set_log_level(&settings::current().log_level);

    let state = Arc::new(AppState::new(db_pool));

    //Run Scheduled jobs that haven't been run yet
    let scheduler_state = Arc::clone(&state);
     tokio::spawn(async move {
        JobExecutor::check_and_run_scheduled_jobs(scheduler_state).await;
    });

    // On startup, clean up logs older than the configured retention window.
    let retention_days = settings::current().log_retention_days;
    let _ = repository::cleanup_old_logs(&state.db, retention_days).await;


    // Handle unfinished jobs in case of previously closed app without finalising all jobs:
    JobExecutor::resume_incomplete_jobs(state.clone()).await;

    let app = Router::new()
        // Job routes
        .route("/api/jobs", post(api::jobs::create_job).get(api::jobs::list_jobs))
        .route("/api/jobs/schedule", post(api::jobs::schedule_job).get(api::jobs::list_jobs))
        .route("/api/jobs/{id}", get(api::jobs::get_job))
        .route("/api/jobs/{id}/cancel", post(api::jobs::cancel_job))
        // Host routes
        .route("/api/hosts", get(api::hosts::list_hosts))
        .route("/api/hosts/{ip}", get(api::hosts::get_host))
        // Display routes
        .route("/api/display/status", get(api::display::get_display_status))
        .route("/api/display/update", post(api::display::update_display))
        // Config routes
        .route("/api/config", get(api::config::get_config).post(api::config::update_config))
        // Logs routes
        .route("/api/logs", get(api::logs::get_all_logs))
        .route("/api/logs/{id}", get(api::logs::get_logs_by_job_id))
        // Export routes
        .route("/api/exports", get(api::exports::list_exports))
        .route("/api/exports/{filename}", get(api::exports::download_export))
        // CVE enrichment routes
        .route("/api/cve", get(api::cve::list_cves))
        .route("/api/cve/sync", post(api::cve::sync_cves))
        .route("/api/cve/{id}", get(api::cve::get_cve))
        // Attack/exploit module registry
        .route("/api/modules", get(api::modules::list_modules))
        // WebSocket route
        .route("/ws", get(api::websocket::ws_handler))
        .with_state(state);

    // Bind to address
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("🚀 Server listening on {}", addr);

    // Create TCP listener
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    // Start server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    tracing::info!("✅ Server has shut down gracefully");
}