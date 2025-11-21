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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use crate::models::HostStatus;

    #[test]
    fn host_new_initializes_correctly() {
        let h = Host::new("192.168.1.10".into());

        assert_eq!(h.ip, "192.168.1.10");
        assert_eq!(h.status, HostStatus::Unknown);
        assert!(h.ports.is_empty());
        assert!(h.services.is_empty());
        assert!(h.vulnerabilities.is_empty());
        assert!(h.banners.is_empty());

        // timestamps should be valid RFC3339
        assert!(DateTime::parse_from_rfc3339(&h.first_seen).is_ok());
        assert!(DateTime::parse_from_rfc3339(&h.last_seen).is_ok());
    }

    #[test]
    fn add_port_adds_new_port() {
        let mut h = Host::new("10.0.0.1".into());

        h.add_port(22, "tcp", "open");

        assert_eq!(h.ports.len(), 1);
        let p = &h.ports[0];
        assert_eq!(p.number, 22);
        assert_eq!(p.protocol, "tcp");
        assert_eq!(p.status, "open");
    }

    #[test]
    fn add_port_updates_existing_port() {
        let mut h = Host::new("10.0.0.1".into());

        h.add_port(22, "tcp", "open");
        h.add_port(22, "tcp", "closed");

        assert_eq!(h.ports.len(), 1);
        assert_eq!(h.ports[0].status, "closed");
    }

    #[test]
    fn add_port_sorts_ports() {
        let mut h = Host::new("10.0.0.1".into());

        h.add_port(443, "tcp", "open");
        h.add_port(22, "tcp", "open");
        h.add_port(80, "tcp", "open");

        let ordered: Vec<u16> = h.ports.iter().map(|p| p.number).collect();
        assert_eq!(ordered, vec![22, 80, 443]);
    }

    #[test]
    fn add_banner_adds_only_once() {
        let mut h = Host::new("10.0.0.1".into());

        h.add_banner("Apache".into());
        h.add_banner("Apache".into());

        assert_eq!(h.banners.len(), 1);
        assert_eq!(h.banners[0], "Apache");
    }

    #[test]
    fn update_last_seen_changes_timestamp() {
        let mut h = Host::new("10.0.0.1".into());

        let old = h.last_seen.clone();
        std::thread::sleep(std::time::Duration::from_millis(5));

        h.update_last_seen();

        assert!(h.last_seen > old);
    }

    #[test]
    fn default_uses_correct_ip() {
        let h = Host::default();
        assert_eq!(h.ip, "0.0.0.0");
    }


}
