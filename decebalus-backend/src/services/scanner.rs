use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use ipnet::{IpNet, Ipv4Net};
use crate::models::Host;
use crate::state::AppState;
use tokio::sync::Semaphore;
use crate::db::repository;
use pnet_datalink::interfaces;



/// Network Scanner Service
/// Discovers alive hosts on the network
pub struct NetworkScanner;

impl NetworkScanner {
    /// Discover hosts on a network
    /// 
    /// # Arguments
    /// * `network` - CIDR notation (e.g., "192.168.1.0/24")
    /// * `state` - Application state to store discovered hosts
    /// 
    /// # Returns
    /// Number of hosts discovered
    pub async fn discover_hosts(target: &str, state: &Arc<AppState>) -> Result<usize, String> {
        let network = if target == "self" {
            Self::detect_local_network()?
        } else {
            target
                .parse::<IpNet>()
                .map_err(|_| format!("Invalid network CIDR: {}", target))?
        };

        Self::log_and_broadcast(state, &format!("Starting network discovery on {}", network));

        let ips: Vec<IpAddr> = network.hosts().collect();
        Self::log_and_broadcast(state, &format!("Scanning {} IPs", ips.len()));

        let hosts_found = Arc::new(tokio::sync::Mutex::new(0));
        let max_discover_threads = std::env::var("MAX_DISCOVER_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(256);
        let sem = Arc::new(Semaphore::new(max_discover_threads));

        let mut futures = FuturesUnordered::new();

        for ip in ips {
            let state_clone = state.clone();
            let hosts_found_clone = hosts_found.clone();
            let sem_clone = sem.clone();

            futures.push(tokio::spawn(async move {
                // acquire semaphore permit
                let _permit = sem_clone.acquire_owned().await.unwrap();

                let ip_str = ip.to_string();
                Self::log_and_broadcast(&state_clone, &format!("Scanning now: {}", ip_str));

                if Self::is_host_alive(&ip_str).await {
                    Self::log_and_broadcast(&state_clone, &format!("Host found: {}", ip_str));

                    let host = Host::new(ip_str.clone());

                    if let Err(e) = repository::upsert_host(&state_clone.db, &host).await {
                        tracing::error!("Failed to save host to database: {}", e);
                    }

                    let _ = state_clone.broadcaster.send(format!("host_found:{}", ip_str));

                    // increment counter safely
                    let mut count = hosts_found_clone.lock().await;
                    *count += 1;
                }
            }));
        }

        // wait for all tasks to complete
        while let Some(_) = futures.next().await {}

        let total = *hosts_found.lock().await;
        tracing::info!("Discovery complete. Found {} hosts", total);
        Ok(total)
    }
    
    /// Check if a host is alive
    /// Uses a simple TCP connection attempt to common ports
    /// 
    /// # Arguments
    /// * `ip` - IP address to check
    /// 
    /// # Returns
    /// true if host responds, false otherwise
    async fn is_host_alive(ip: &str) -> bool {
        // Probe a broad set of ports to cover servers, IoT devices, printers, etc.
        // Connection refused is an instant response and also confirms the host is up.
        let ports = [
            80, 443, 8080, 8443,        // HTTP/S
            22, 23,                      // SSH, Telnet
            21,                          // FTP
            25, 587,                     // SMTP
            445, 139,                    // SMB
            3389,                        // RDP
            3306, 5432,                  // MySQL, PostgreSQL
            6379,                        // Redis
            9100,                        // Printer JetDirect
            1883, 8883,                  // MQTT (IoT)
            5000, 8888,                  // Common dev/API ports
        ];

        let mut handles = Vec::new();
        for port in ports {
            let addr = format!("{}:{}", ip, port);
            handles.push(tokio::spawn(async move {
                tokio::time::timeout(
                    Duration::from_millis(500),
                    tokio::net::TcpStream::connect(&addr),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false)
            }));
        }

        for handle in handles {
            if let Ok(true) = handle.await {
                return true;
            }
        }
        false
    }

    pub fn detect_local_network() -> Result<IpNet, String> {
        let interfaces = interfaces();

        for iface in interfaces {
            if !iface.is_up() || iface.is_loopback() {
                continue;
            }
            // skip docker/vpn/etc
            if iface.name.starts_with("docker")
                || iface.name.starts_with("veth")
                || iface.name.starts_with("tun")
            {
                continue;
            }
            for ip in iface.ips {
                match ip.ip() {
                    IpAddr::V4(v4) => {
                        if v4.is_loopback() || v4.is_link_local() {
                            continue;
                        }

                        let prefix = ip.prefix();
                        let net = Ipv4Net::new(v4, prefix)
                            .map_err(|e| e.to_string())?
                            .trunc();

                        return Ok(IpNet::V4(net));
                    }
                    IpAddr::V6(_) => continue,
                }
            }
            // for ip in iface.ips {
            //     // Skip loopback / link-local
            //     if let std::net::IpAddr::V4(v4) = ip.ip() {
            //         if v4.is_loopback() || v4.is_link_local() {
            //             continue;
            //         }
            //         return Ok(ip);
            //     }
            //     return Ok(ip);
            // }
        }
        Err("No suitable local network interface found".to_string())
    }

    fn log_and_broadcast(state: &Arc<AppState>, message: &str) {
        tracing::info!("{}", message);
        let _ = state.broadcaster.send(format!("log:{}", message));
    }

}