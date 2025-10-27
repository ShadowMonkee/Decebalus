use tokio::sync::broadcast;
use crate::db::DbPool;

#[derive(Clone)]
pub struct AppState {
    /// Broadcast channel for real-time events (WebSocket)
    pub broadcaster: broadcast::Sender<String>,
    
    /// Database connection pool
    pub db: DbPool,
    pub max_threads: usize, 
}

impl AppState {
    /// Create a new AppState
    pub fn new(db: DbPool) -> Self {
        let (tx, _rx) = broadcast::channel(100);

        let max_threads = std::env::var("MAX_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(5);
        
        Self {
            broadcaster: tx,
            db,
            max_threads,
        }
    }
}