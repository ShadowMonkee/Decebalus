use std::sync::Arc;

use tokio::sync::{Semaphore, broadcast};
use crate::db::DbPool;

#[derive(Clone)]
pub struct AppState {
    /// Broadcast channel for real-time events (WebSocket)
    pub broadcaster: broadcast::Sender<String>,

    /// Database connection pool
    pub db: DbPool,

    /// Bounds the number of concurrently-running jobs (worker pool). Sized at
    /// startup from settings; per-scan knobs are read live via [`crate::settings::current`].
    pub semaphore: Arc<Semaphore>,
}

impl AppState {
    /// Create a new AppState. The worker-pool size is fixed here at startup from
    /// the resolved settings; changing it requires a restart.
    pub fn new(db: DbPool) -> Self {
        let (tx, _rx) = broadcast::channel(100);

        let s = crate::settings::current();

        Self {
            broadcaster: tx,
            db,
            semaphore: Arc::new(Semaphore::new(s.max_threads)),
        }
    }
}