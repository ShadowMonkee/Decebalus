use std::sync::Arc;
use std::time::Duration;
use crate::models::Host;
use crate::AppState;
use ipnetwork::Ipv4Network;


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
    pub async fn discover_hosts(network: &str, state: &Arc<AppState>) -> Result<usize, String> {
        tracing::info!("Starting network discovery on {}", network);
        
        // Parse network CIDR
        let (base_ip, range) = Self::parse_network(network)?;
        
        tracing::info!("Scanning {} IPs in range {}", range, network);
        
        let mut hosts_found = 0;
        
        // Scan each IP in range
        for i in 1..=range {
            let ip = format!("{}.{}", base_ip, i);
            tracing::info!("Scanning now: {}", ip);
            
            if Self::is_host_alive(&ip).await {
                tracing::info!("Host found: {}", ip);
                
                // Create host entry
                let host = Host::new(ip.clone());
                
                // Add to state
                {
                    let mut hosts = state.hosts.lock().await;
                    // Check if host already exists
                    if let Some(existing) = hosts.iter_mut().find(|h| h.ip == ip) {
                        existing.update_last_seen();
                    } else {
                        hosts.push(host);
                    }
                }
                
                // Broadcast discovery
                let _ = state.broadcaster.send(format!("host_found:{}", ip));
                
                hosts_found += 1;
            }
        }
        
        tracing::info!("Discovery complete. Found {} hosts", hosts_found);
        Ok(hosts_found)
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
}