// Thin binary over the `decebalus_backend` library crate (which holds all the
// modules). This avoids compiling the whole crate twice.
use axum::{
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, sync::Arc};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;

use decebalus_backend::db::repository;
use decebalus_backend::services::{DisplayService, JobExecutor, Orchestrator};
use decebalus_backend::state::AppState;
use decebalus_backend::{api, db, settings};

/// Web UI baked into the binary at compile time (`--features embed-ui`, built via
/// `scripts/build.sh`) instead of served from a `dist/` folder on disk.
#[cfg(feature = "embed-ui")]
mod embedded_ui {
    use axum::http::{header, StatusCode, Uri};
    use axum::response::{IntoResponse, Response};
    use rust_embed::RustEmbed;

    #[derive(RustEmbed)]
    #[folder = "../decebalus-frontend/dist"]
    struct Assets;

    /// Serve an embedded asset by request path; unknown paths (SPA client routes)
    /// fall back to `index.html`, mirroring the on-disk `ServeDir` behavior.
    pub async fn serve(uri: Uri) -> Response {
        let path = uri.path().trim_start_matches('/');
        if let Some(file) = Assets::get(path) {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            return ([(header::CONTENT_TYPE, mime.as_ref().to_string())], file.data.into_owned()).into_response();
        }
        match Assets::get("index.html") {
            Some(file) => ([(header::CONTENT_TYPE, "text/html")], file.data.into_owned()).into_response(),
            None => (
                StatusCode::NOT_FOUND,
                "web UI not embedded — dist/ was empty at compile time; rebuild with scripts/build.sh",
            )
                .into_response(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // Doesn't boot the server (which would spin up the autonomous scanning
        // loop) — just confirms the built `dist/` was actually baked into this
        // binary at compile time via `--features embed-ui`.
        #[test]
        fn dist_output_is_embedded() {
            assert!(Assets::get("index.html").is_some(), "run scripts/build.sh so dist/ exists before compiling");
        }
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    tracing::info!("Signal received, shutting down");
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    // `decebalus-backend doctor` → report on external tool dependencies and exit.
    if std::env::args().nth(1).as_deref() == Some("doctor") {
        decebalus_backend::doctor::print_report();
        return;
    }

    // `decebalus-backend loot decrypt <path>` → decrypt a loot file to stdout.
    // Loot lives under `<LOOT_DIR>/<engagement-id-or-"global">/<file>`, so the
    // engagement (and thus which derived key to use) is read straight off the path.
    if std::env::args().nth(1).as_deref() == Some("loot") {
        let sub = std::env::args().nth(2);
        let path = std::env::args().nth(3);
        let (Some("decrypt"), Some(path)) = (sub.as_deref(), path.as_deref()) else {
            eprintln!("usage: decebalus-backend loot decrypt <path>");
            std::process::exit(1);
        };
        if let Err(e) = decebalus_backend::services::crypto::init(std::path::Path::new("data")) {
            eprintln!("crypto init failed: {}", e);
            std::process::exit(1);
        }
        let eng_dir = std::path::Path::new(path)
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("global");
        let engagement_id = if eng_dir == "global" { "" } else { eng_dir };
        let raw = match std::fs::read(path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("cannot read {}: {}", path, e);
                std::process::exit(1);
            }
        };
        match decebalus_backend::services::crypto::decrypt(engagement_id, &raw) {
            Ok(plain) => {
                use std::io::Write;
                std::io::stdout().write_all(&plain).expect("stdout write failed");
                return;
            }
            Err(e) => {
                eprintln!("decrypt failed: {}", e);
                std::process::exit(1);
            }
        }
    }

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

    // Load (or generate) the master key before anything touches the credential
    // store or loot, so every encrypt/decrypt call downstream sees the real key.
    decebalus_backend::services::crypto::init(std::path::Path::new("data"))
        .expect("Failed to initialize secrets-at-rest master key");

    let db_pool = db::init_pool(&database_url)
        .await
        .expect("Failed to initialize database");

    // Resolve runtime settings from the config table (env/defaults as fallback) and
    // apply the persisted log level.
    settings::init(settings::Settings::load(&db_pool).await);
    settings::set_log_level(&settings::current().log_level);

    // Register the shipped SecLists wordlists in the background. The first-boot scan
    // walks ~1 GB of lists, so spawning it keeps server startup instant; it's a cheap
    // no-op on every subsequent boot.
    {
        let pool = db_pool.clone();
        tokio::spawn(async move {
            decebalus_backend::services::wordlists::seed_bundled(&pool).await;
        });
    }

    let state = Arc::new(AppState::new(db_pool));

    //Run Scheduled jobs that haven't been run yet
    let scheduler_state = Arc::clone(&state);
     tokio::spawn(async move {
        JobExecutor::check_and_run_scheduled_jobs(scheduler_state).await;
    });

    // Autonomous operation loop (gated by the autonomous_* settings; recon-only by default).
    let orchestrator_state = Arc::clone(&state);
    tokio::spawn(async move {
        Orchestrator::run(orchestrator_state).await;
    });

    // Status display service (mock renderer by default; e-paper with `--features hardware`).
    let display_state = Arc::clone(&state);
    tokio::spawn(async move {
        DisplayService::run(display_state).await;
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
        // Wordlists: bundled SecLists (shipped, offline) + user-saved custom lists
        .route("/api/wordlists", get(api::wordlists::list_wordlists))
        .route("/api/wordlists/{id}/content", get(api::wordlists::get_wordlist_content))
        .route("/api/wordlists/custom", post(api::wordlists::save_custom_wordlist))
        .route("/api/wordlists/{id}", axum::routing::delete(api::wordlists::delete_wordlist))
        // Change-detection history
        .route("/api/history", get(api::history::list_history))
        // Next-move rule engine + findings (the "war table")
        .route("/api/findings", get(api::findings::list_findings))
        .route("/api/findings/{id}/run", post(api::findings::run_finding))
        .route("/api/findings/{id}/dismiss", post(api::findings::dismiss_finding))
        .route("/api/engine/run", post(api::findings::run_engine))
        // Engagements (scope + starting credential) and the credential vault
        .route("/api/engagements", get(api::engagements::list_engagements).post(api::engagements::create_engagement))
        .route("/api/engagements/active", get(api::engagements::active_engagement))
        .route("/api/engagements/{id}/activate", post(api::engagements::activate_engagement))
        .route("/api/credentials", get(api::engagements::list_credentials))
        // WebSocket route
        .route("/ws", get(api::websocket::ws_handler));

    // Serve the web UI so one process hosts both API and UI. Deep links fall back
    // to index.html for the SPA router. `embed-ui` bakes the UI into the binary
    // (built via scripts/build.sh); otherwise it's served from disk (dev default —
    // point FRONTEND_DIR at a `npm run build` output, or run Vite separately).
    #[cfg(feature = "embed-ui")]
    let app = app.fallback(embedded_ui::serve);
    #[cfg(not(feature = "embed-ui"))]
    let app = {
        let frontend_dir = std::env::var("FRONTEND_DIR")
            .unwrap_or_else(|_| "../decebalus-frontend/dist".to_string());
        app.fallback_service(
            tower_http::services::ServeDir::new(&frontend_dir)
                .not_found_service(tower_http::services::ServeFile::new(format!("{frontend_dir}/index.html"))),
        )
    };

    let app = app
        // Optional bearer-token gate (active only when DECEBALUS_TOKEN is set).
        .layer(axum::middleware::from_fn(api::auth::require_token))
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