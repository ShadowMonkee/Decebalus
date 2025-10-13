use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use crate::models::{Job, Host, DisplayStatus, Config};

/// Shared application state
/// Contains all the data that needs to be shared across HTTP handlers
#[derive(Clone, Debug)]
pub struct AppState {
    /// Broadcast channel for real-time events (WebSocket)
    pub broadcaster: broadcast::Sender<String>,
    
    /// In-memory storage for jobs
    /// TODO: Replace with database persistence
    pub jobs: Arc<Mutex<Vec<Job>>>,
    
    /// In-memory storage for discovered hosts
    /// TODO: Replace with database persistence
    pub hosts: Arc<Mutex<Vec<Host>>>,
    
    /// E-Paper display status
    pub display_status: Arc<Mutex<DisplayStatus>>,
    
    /// Application configuration
    pub config: Arc<Mutex<Config>>,
}

impl AppState {
    /// Create a new AppState with default values
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(100);
        
        Self {
            broadcaster: tx,
            jobs: Arc::new(Mutex::new(Vec::new())),
            hosts: Arc::new(Mutex::new(Vec::new())),
            display_status: Arc::new(Mutex::new(DisplayStatus::new())),
            config: Arc::new(Mutex::new(Config::new())),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}