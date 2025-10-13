use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DisplayStatus {
    pub status: String,
    pub last_update: String,
}

impl DisplayStatus {
    pub fn new() -> Self {
        Self {
            status: "idle".to_string(),
            last_update: "never".to_string(),
        }
    }
    
    pub fn update(&mut self, status: String) {
        self.status = status;
        self.last_update = chrono::Utc::now().to_rfc3339();
    }
}

impl Default for DisplayStatus {
    fn default() -> Self {
        Self::new()
    }
}