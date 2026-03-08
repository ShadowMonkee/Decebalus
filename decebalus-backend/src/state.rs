use std::sync::Arc;

use tokio::sync::{Semaphore, broadcast};
use crate::db::DbPool;

#[derive(Clone)]
pub struct AppState {
    /// Broadcast channel for real-time events (WebSocket)
    pub broadcaster: broadcast::Sender<String>,
    
    /// Database connection pool
    pub db: DbPool,
    pub max_threads: usize,
    pub max_scan_concurrency: usize,
    pub semaphore: Arc<Semaphore>,
}

impl AppState {
    /// Create a new AppState
    pub fn new(db: DbPool) -> Self {
        let (tx, _rx) = broadcast::channel(100);

        let max_threads = std::env::var("MAX_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(5);

        let max_scan_concurrency = std::env::var("MAX_SCAN_CONCURRENCY")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(500);

        Self {
            broadcaster: tx,
            db,
            max_threads,
            max_scan_concurrency,
            semaphore: Arc::new(Semaphore::new(max_threads)),
        }
    }
}