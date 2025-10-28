mod api;
mod db;
mod models;
mod services;
mod state;

use axum::{
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, sync::Arc};
use tracing_subscriber;

pub use state::AppState;

use crate::services::JobExecutor;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    tracing::info!("Signal received, shutting down");
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:data/decebalus.db".to_string());
    
    std::fs::create_dir_all("data").expect("Failed to create data directory");
    
    let db_pool = db::init_pool(&database_url)
        .await
        .expect("Failed to initialize database");

    let state = Arc::new(AppState::new(db_pool));

    // Handle unfinished jobs in case of previously closed app without finalising all jobs:
    JobExecutor::resume_incomplete_jobs(state.clone()).await;

    let app = Router::new()
        // Job routes
        .route("/api/jobs", post(api::jobs::create_job).get(api::jobs::list_jobs))
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