use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use ipnet::IpNet;
use crate::models::Host;
use crate::state::AppState;
use ipnetwork::Ipv4Network;
use tokio::sync::Semaphore;
use crate::db::repository;



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
    pub async fn discover_hosts(network: IpNet, state: &Arc<AppState>) -> Result<usize, String> {
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
    
    /// Parse network CIDR notation
    /// 
    /// # Arguments
    /// * `network` - CIDR notation (e.g., "192.168.1.0/24")
    /// 
    /// # Returns
    /// Tuple of (base_ip, range_size)
    fn parse_network(network: &str) -> Result<(String, u32), String> {
        // Try to parse the CIDR using ipnetwork
        match network.parse::<Ipv4Network>() {
            Ok(net) => {
                // Example: 192.168.1.0/24 → base_ip = "192.168.1", range = 254
                let base_ip = net.network().octets();
                
                // Calculate number of usable host addresses
                let total_ips = (2u32.pow((32 - net.prefix()) as u32)).saturating_sub(2);
                
                let base_ip_str = format!("{}.{}.{}", base_ip[0], base_ip[1], base_ip[2]);
                Ok((base_ip_str, total_ips))
            }
            Err(_) => Err(format!("Invalid CIDR notation: {}", network)),
        }
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
        // Try to connect to common ports (faster than ICMP ping)
        let common_ports = [80, 443, 22, 21, 445, 3389];
        
        for port in common_ports {
            let addr = format!("{}:{}", ip, port);
            
            // Try to connect with short timeout
            match tokio::time::timeout(
                Duration::from_millis(500),
                tokio::net::TcpStream::connect(&addr)
            ).await {
                Ok(Ok(_)) => {
                    // Connection successful - host is alive
                    return true;
                }
                _ => continue,
            }
        }
        
        false
    }

    fn log_and_broadcast(state: &Arc<AppState>, message: &str) {
        tracing::info!("{}", message);
        let _ = state.broadcaster.send(format!("log:{}", message));
    }

}