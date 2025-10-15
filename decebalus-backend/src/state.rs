use tokio::sync::broadcast;
use crate::db::DbPool;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    /// Broadcast channel for real-time events (WebSocket)
    pub broadcaster: broadcast::Sender<String>,
    
    /// Database connection pool
    pub db: DbPool,
}

impl AppState {
    /// Create a new AppState
    pub fn new(db: DbPool) -> Self {
        let (tx, _rx) = broadcast::channel(100);
        
        Self {
            broadcaster: tx,
            db,
        }
    }
}