use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Host {
    pub ip: String,
    pub ports: Vec<u16>,
    pub banners: Vec<String>,
    pub last_seen: String,
}

impl Host {
    pub fn new(ip: String) -> Self {
        Self {
            ip,
            ports: Vec::new(),
            banners: Vec::new(),
            last_seen: chrono::Utc::now().to_rfc3339(),
        }
    }
    
    pub fn add_port(&mut self, port: u16) {
        if !self.ports.contains(&port) {
            self.ports.push(port);
            self.ports.sort();
        }
    }
    
    pub fn add_banner(&mut self, banner: String) {
        if !self.banners.contains(&banner) {
            self.banners.push(banner);
        }
    }
    
    pub fn update_last_seen(&mut self) {
        self.last_seen = chrono::Utc::now().to_rfc3339();
    }
}