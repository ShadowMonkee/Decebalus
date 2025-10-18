use std::sync::Arc;
use std::time::Duration;
use crate::AppState;
use crate::db::repository;
use crate::models::Port;

/// Port Scanner Service
/// Scans for open ports on hosts
pub struct PortScanner;

impl PortScanner {
    /// Scan a single host for open ports
    pub async fn scan_host(ip: &str, state: &Arc<AppState>) -> Result<usize, String> {
        tracing::info!("Starting port scan on {}", ip);

        let ports_to_scan = Self::get_port_range(state).await;
        let mut open_ports = Vec::new();

        for port_num in ports_to_scan {
            if Self::is_port_open(ip, port_num).await {
                tracing::debug!("Port {} open on {}", port_num, ip);

                // Build port model
                let port = Port {
                    number: port_num,
                    protocol: Self::infer_protocol(port_num),
                    status: "open".to_string(),
                };

                open_ports.push(port.clone());

                // Try to grab banner
                if let Some(banner) = Self::grab_banner(ip, port_num).await {
                    tracing::debug!("Banner from {}:{} - {}", ip, port_num, banner);
                    Self::add_banner_to_host(state, ip, banner).await;
                }
            }
        }

        // Update host with discovered ports
        if !open_ports.is_empty() {
            Self::update_host_ports(state, ip, open_ports.clone()).await;
            tracing::info!("Found {} open ports on {}", open_ports.len(), ip);
        }

        Ok(open_ports.len())
    }

    /// Get port range to scan from DB config or defaults
    async fn get_port_range(state: &Arc<AppState>) -> Vec<u16> {
        if let Ok(config) = repository::get_config(&state.db).await {
            if let Some(ports) = config.settings
                .get("scan_config")
                .and_then(|c| c.get("port_range"))
                .and_then(|p| p.as_array())
            {
                return ports.iter()
                    .filter_map(|p| p.as_u64().map(|n| n as u16))
                    .collect();
            }
        }
        Self::common_ports()
    }

    /// Common ports to scan (if no config specified)
    fn common_ports() -> Vec<u16> {
        vec![
            80, 443, 8080, 8443, // Web
            22, 23,              // SSH/Telnet
            21, 20,              // FTP
            25, 110, 143, 465, 587, 993, 995, // Mail
            3306, 5432, 1433, 27017, // Databases
            139, 445, 135,       // SMB/Windows
            3389,                // RDP
            53, 161, 1521, 6379, 9200, // Other
        ]
    }

    /// Guess protocol based on common port numbers
    fn infer_protocol(port: u16) -> String {
        match port {
            80 | 8080 | 8443 => "http".to_string(),
            443 => "https".to_string(),
            22 => "ssh".to_string(),
            21 | 20 => "ftp".to_string(),
            25 | 465 | 587 => "smtp".to_string(),
            110 | 995 => "pop3".to_string(),
            143 | 993 => "imap".to_string(),
            3306 => "mysql".to_string(),
            5432 => "postgresql".to_string(),
            1433 => "mssql".to_string(),
            27017 => "mongodb".to_string(),
            139 | 445 | 135 => "smb".to_string(),
            3389 => "rdp".to_string(),
            53 => "dns".to_string(),
            161 => "snmp".to_string(),
            1521 => "oracle".to_string(),
            6379 => "redis".to_string(),
            9200 => "elasticsearch".to_string(),
            _ => "unknown".to_string(),
        }
    }

    /// Check if a port is open
    async fn is_port_open(ip: &str, port: u16) -> bool {
        let addr = format!("{}:{}", ip, port);
        match tokio::time::timeout(
            Duration::from_millis(1000),
            tokio::net::TcpStream::connect(&addr)
        ).await {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }

    /// Attempt to grab and clean a service banner
    async fn grab_banner(ip: &str, port: u16) -> Option<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let addr = format!("{}:{}", ip, port);

        match tokio::time::timeout(
            Duration::from_secs(2),
            async {
                let mut stream = tokio::net::TcpStream::connect(&addr).await?;

                if [80, 8080, 8000, 443].contains(&port) {
                    let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
                } else if port == 21 {
                    let _ = stream.write_all(b"HELP\r\n").await;
                }

                let mut buffer = vec![0u8; 1024];
                let n = stream.read(&mut buffer).await?;

                if n > 0 {
                    let raw_banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                    let clean_banner = Self::prettify_banner(&raw_banner);
                    return Ok(Some(clean_banner));
                }

                Ok::<Option<String>, std::io::Error>(None)
            },
        )
        .await
        {
            Ok(Ok(Some(banner))) => Some(banner),
            _ => None,
        }
    }

    /// Clean and format banner nicely
    fn prettify_banner(raw: &str) -> String {
        raw.replace("\r", "")
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .take(4)
            .collect::<Vec<_>>()
            .join(" | ")
    }

    /// Update host with discovered ports
    async fn update_host_ports(state: &Arc<AppState>, ip: &str, ports: Vec<Port>) {
        if let Ok(Some(mut host)) = repository::get_host(&state.db, ip).await {
            for port in ports {
                host.add_port(port.number, &port.protocol, &port.status);
            }
            host.update_last_seen();

            if let Err(e) = repository::upsert_host(&state.db, &host).await {
                tracing::error!("Failed to update host ports: {}", e);
            }
        }
    }

    /// Add banner to host
    async fn add_banner_to_host(state: &Arc<AppState>, ip: &str, banner: String) {
        if let Ok(Some(mut host)) = repository::get_host(&state.db, ip).await {
            host.add_banner(banner);
        }
    }
}
