use std::sync::Arc;
use std::time::Duration;
use crate::AppState;

/// Port Scanner Service
/// Scans for open ports on hosts
pub struct PortScanner;

impl PortScanner {
    /// Scan a single host for open ports
    /// 
    /// # Arguments
    /// * `ip` - IP address to scan
    /// * `state` - Application state to update host information
    /// 
    /// # Returns
    /// Number of open ports found
    pub async fn scan_host(ip: &str, state: &Arc<AppState>) -> Result<usize, String> {
        tracing::info!("Starting port scan on {}", ip);
        
        // Get port range from config (or use default)
        let ports_to_scan = Self::get_port_range(state).await;
        
        let mut open_ports = Vec::new();
        
        // Scan each port
        for port in ports_to_scan {
            if Self::is_port_open(ip, port).await {
                tracing::debug!("Port {} open on {}", port, ip);
                open_ports.push(port);
                
                // Try to grab banner
                if let Some(banner) = Self::grab_banner(ip, port).await {
                    tracing::debug!("Banner from {}:{} - {}", ip, port, banner);
                    
                    // Update host with banner
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
    
    /// Get port range to scan from config
    async fn get_port_range(state: &Arc<AppState>) -> Vec<u16> {
        let config = state.config.lock().await;
        
        // Check if custom port range is configured
        if let Some(ports) = config.settings
            .get("scan_config")
            .and_then(|c| c.get("port_range"))
            .and_then(|p| p.as_array())
        {
            return ports
                .iter()
                .filter_map(|p| p.as_u64().map(|n| n as u16))
                .collect();
        }
        
        // Default: common ports
        Self::common_ports()
    }
    
    /// Common ports to scan (if no config specified)
    fn common_ports() -> Vec<u16> {
        vec![
            // Web
            80, 443, 8080, 8443,
            // SSH/Telnet
            22, 23,
            // FTP
            21, 20,
            // Mail
            25, 110, 143, 465, 587, 993, 995,
            // Database
            3306, 5432, 1433, 27017,
            // SMB/Windows
            139, 445, 135,
            // RDP
            3389,
            // Other
            53, 161, 1521, 6379, 9200,
        ]
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
    
    /// Attempt to grab service banner
    /// Attempt to grab and clean a service banner
    async fn grab_banner(ip: &str, port: u16) -> Option<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let addr = format!("{}:{}", ip, port);

        // Try to connect and read banner
        match tokio::time::timeout(
            Duration::from_secs(2),
            async {
                let mut stream = tokio::net::TcpStream::connect(&addr).await?;

                // Send simple probe for common ports
                if [80, 8080, 8000, 443].contains(&port) {
                    let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
                } else if port == 21 {
                    let _ = stream.write_all(b"HELP\r\n").await;
                } else if port == 22 {
                    // SSH banners come automatically
                }

                // Read response
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

    /// Clean and format banner string nicely
    fn prettify_banner(raw: &str) -> String {
        // Split lines, trim spaces, remove empties
        let lines: Vec<String> = raw
            .replace("\r", "")
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        // Option 1: show first 3–4 important lines
        let limited: Vec<String> = lines.iter().take(4).cloned().collect();

        // Option 2: compress into single readable line
        limited.join(" | ")
    }
    
    /// Update host with discovered ports
    async fn update_host_ports(state: &Arc<AppState>, ip: &str, ports: Vec<u16>) {
        let mut hosts = state.hosts.lock().await;
        
        if let Some(host) = hosts.iter_mut().find(|h| h.ip == ip) {
            for port in ports {
                host.add_port(port);
            }
            host.update_last_seen();
        }
    }
    
    /// Add banner to host
    async fn add_banner_to_host(state: &Arc<AppState>, ip: &str, banner: String) {
        let mut hosts = state.hosts.lock().await;
        
        if let Some(host) = hosts.iter_mut().find(|h| h.ip == ip) {
            host.add_banner(banner);
        }
    }
}