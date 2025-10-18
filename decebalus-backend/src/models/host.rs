use chrono::Utc;
use serde::{Deserialize, Serialize};
use crate::models::{HostStatus, Port, Service, Vulnerability};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Host {
    pub ip: String,
    pub ports: Vec<Port>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub device_type: Option<String>,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub status: HostStatus,
    pub last_seen: String,
    #[serde(default = "default_first_seen")]
    pub first_seen: String,
    pub services: Vec<Service>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub banners: Vec<String>,
}

fn default_first_seen() -> String {
    Utc::now().to_rfc3339()
}

impl Host {
    pub fn new(ip: String) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            ip,
            ports: Vec::new(),
            os: None,
            os_version: None,
            device_type: None,
            mac_address: None,
            hostname: None,
            status: HostStatus::Unknown,
            last_seen: now.clone(),
            first_seen: now,
            services: Vec::new(),
            vulnerabilities: Vec::new(),
            banners: Vec::new(),
        }
    }

    
    pub fn add_port(&mut self, number: u16, protocol: &str, status: &str) {
        // Check if the port already exists
        if let Some(existing) = self.ports.iter_mut().find(|p| p.number == number && p.protocol == protocol) {
            // Update status if changed
            if existing.status != status {
                existing.status = status.to_string();
            }
        } else {
            // Otherwise, add a new one
            self.ports.push(Port {
                number,
                protocol: protocol.to_string(),
                status: status.to_string(),
            });
        }

        // Keep ports sorted by number, then by protocol for consistency
        self.ports.sort_by(|a, b| {
            a.number
                .cmp(&b.number)
                .then_with(|| a.protocol.cmp(&b.protocol))
        });
    }

    
    pub fn add_banner(&mut self, banner: String) {
        if !self.banners.contains(&banner) {
            self.banners.push(banner);
        }
    }
    
    pub fn update_last_seen(&mut self) {
        self.last_seen = Utc::now().to_rfc3339();
    }
}

impl Default for Host {
    fn default() -> Self {
        Self::new("0.0.0.0".to_string())
    }
}