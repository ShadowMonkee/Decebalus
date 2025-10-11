use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{broadcast, Mutex};
use tracing_subscriber;
use uuid::Uuid;

#[derive(Clone, Debug)]
struct AppState {
    broadcaster: broadcast::Sender<String>,
    jobs: Arc<Mutex<Vec<Job>>>,
    hosts: Arc<Mutex<Vec<Host>>>,
    display_status: Arc<Mutex<DisplayStatus>>,
    config: Arc<Mutex<Config>>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
struct Job {
    id: String,
    job_type: String,
    status: String,
    results: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
struct Host {
    ip: String,
    ports: Vec<u16>,
    banners: Vec<String>,
    last_seen: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
struct DisplayStatus {
    status: String,
    last_update: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
struct Config {
    settings: serde_json::Value,
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    tracing::info!("Signal received, shutting down");
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let (tx, _rx) = broadcast::channel(100);
    let state = AppState {
        broadcaster: tx,
        jobs: Arc::new(Mutex::new(Vec::new())),
        hosts: Arc::new(Mutex::new(Vec::new())),
        display_status: Arc::new(Mutex::new(DisplayStatus {
            status: "idle".to_string(),
            last_update: "never".to_string(),
        })),
        config: Arc::new(Mutex::new(Config {
            settings: serde_json::json!({}),
        })),
    };

    let shared_state = Arc::new(state);

    let app = Router::new()
        .route("/api/jobs", post(create_job).get(list_jobs))
        .route("/api/jobs/{id}", get(get_job))
        .route("/api/jobs/{id}/cancel", post(cancel_job))
        .route("/api/hosts", get(list_hosts))
        .route("/api/hosts/{ip}", get(get_host))
        .route("/api/display/status", get(get_display_status))
        .route("/api/display/update", post(update_display))
        .route("/api/config", get(get_config).post(update_config))
        .route("/ws", get(ws_handler))
        .with_state(shared_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    tracing::info!("Server has shut down gracefully");
}

// Job endpoints
async fn create_job(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let job_type = payload
        .get("job_type")
        .and_then(|v| v.as_str())
        .unwrap_or("discovery")
        .to_string();

    let job = Job {
        id: Uuid::new_v4().to_string(),
        job_type: job_type.clone(),
        status: "queued".to_string(),
        results: None,
    };

    {
        let mut jobs = state.jobs.lock().await;
        jobs.push(job.clone());
    }

    let _ = state
        .broadcaster
        .send(format!("job_queued:{}:{}", job.id, job_type));

    (axum::http::StatusCode::CREATED, Json(job))
}

async fn list_jobs(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let jobs = state.jobs.lock().await;
    Json(jobs.clone())
}

async fn get_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let jobs = state.jobs.lock().await;
    
    if let Some(job) = jobs.iter().find(|j| j.id == id) {
        (axum::http::StatusCode::OK, Json(job.clone())).into_response()
    } else {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Job with ID {} not found", id)})),
        )
            .into_response()
    }
}

async fn cancel_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut jobs = state.jobs.lock().await;
    
    if let Some(job) = jobs.iter_mut().find(|j| j.id == id) {
        job.status = "cancelled".to_string();
        let _ = state.broadcaster.send(format!("job_cancelled:{}", id));
        
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({
                "message": format!("Cancelling job with {} ID", id)
            })),
        )
    } else {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Job with ID {} not found", id)})),
        )
    }
}

// Host endpoints
async fn list_hosts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let hosts = state.hosts.lock().await;
    Json(hosts.clone())
}

async fn get_host(
    State(state): State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    let hosts = state.hosts.lock().await;
    
    if let Some(host) = hosts.iter().find(|h| h.ip == ip) {
        (axum::http::StatusCode::OK, Json(host.clone())).into_response()
    } else {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Host with IP {} not found", ip)})),
        )
            .into_response()
    }
}

// Display endpoints
async fn get_display_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let status = state.display_status.lock().await;
    Json(status.clone())
}

async fn update_display(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let text = payload
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or("No text provided");
    
    let mut display_status = state.display_status.lock().await;
    display_status.last_update = chrono::Utc::now().to_rfc3339();
    display_status.status = "updated".to_string();
    
    let _ = state.broadcaster.send(format!("display_updated:{}", text));
    
    Json(serde_json::json!({
        "message": format!("Updating e-paper display with: {}", text),
        "status": "success"
    }))
}

// Config endpoints
async fn get_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let config = state.config.lock().await;
    Json(config.clone())
}

async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut config = state.config.lock().await;
    config.settings = payload;
    
    Json(serde_json::json!({
        "message": "Configuration updated successfully",
        "status": "success"
    }))
}

// WebSocket handler
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.broadcaster.subscribe();

    // Spawn task to forward broadcast messages to client
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    // Spawn task to handle incoming messages from client
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(t) => {
                    tracing::info!("Received message from client: {}", t);
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }

    tracing::info!("websocket closed");
}