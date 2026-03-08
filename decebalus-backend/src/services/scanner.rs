use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use ipnet::{IpNet, Ipv4Net};
use crate::models::{Host, HostStatus};
use crate::state::AppState;
use tokio::sync::Semaphore;
use crate::db::repository;
use pnet_datalink::{interfaces, Channel, MacAddr, NetworkInterface};
use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet_packet::Packet;

/// Network Scanner Service
/// Discovers alive hosts on the network
pub struct NetworkScanner;

impl NetworkScanner {
    /// Discover hosts on a network using ARP (primary) or TCP probing (fallback).
    pub async fn discover_hosts(target: &str, state: &Arc<AppState>) -> Result<usize, String> {
        let network = if target == "self" {
            Self::detect_local_network()?
        } else {
            target
                .parse::<IpNet>()
                .map_err(|_| format!("Invalid network CIDR: {}", target))?
        };

        Self::log_and_broadcast(state, &format!("Starting network discovery on {}", network));

        let ips: Vec<Ipv4Addr> = match &network {
            IpNet::V4(net) => net.hosts().collect(),
            IpNet::V6(_) => return Err("IPv6 scanning not supported".to_string()),
        };

        Self::log_and_broadcast(state, &format!("Scanning {} IPs", ips.len()));

        let arp_results = Self::arp_scan(&ips).await;

        let hosts_found = if !arp_results.is_empty() {
            Self::log_and_broadcast(state, &format!("ARP scan found {} hosts", arp_results.len()));
            Self::save_arp_results(state, arp_results).await
        } else {
            Self::log_and_broadcast(state, "ARP unavailable, falling back to TCP probe");
            Self::tcp_discover(&ips, state).await
        };

        tracing::info!("Discovery complete. Found {} hosts", hosts_found);
        Ok(hosts_found)
    }

    /// Try ARP scan. Returns empty map if raw sockets are unavailable.
    async fn arp_scan(targets: &[Ipv4Addr]) -> HashMap<Ipv4Addr, String> {
        let Some((iface, source_ip, source_mac, _)) = Self::detect_local_interface_info() else {
            return HashMap::new();
        };

        let targets_owned = targets.to_vec();
        tokio::task::spawn_blocking(move || {
            Self::arp_scan_blocking(iface, source_ip, source_mac, targets_owned)
        })
        .await
        .unwrap_or_default()
    }

    fn arp_scan_blocking(
        iface: NetworkInterface,
        source_ip: Ipv4Addr,
        source_mac: MacAddr,
        targets: Vec<Ipv4Addr>,
    ) -> HashMap<Ipv4Addr, String> {
        let config = pnet_datalink::Config {
            read_timeout: Some(Duration::from_millis(100)),
            ..Default::default()
        };

        let (mut tx, mut rx) = match pnet_datalink::channel(&iface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return HashMap::new(),
        };

        // Send ARP request for each target
        for target_ip in &targets {
            let mut arp_buf = [0u8; 28];
            {
                let mut arp = MutableArpPacket::new(&mut arp_buf).unwrap();
                arp.set_hardware_type(ArpHardwareTypes::Ethernet);
                arp.set_protocol_type(EtherTypes::Ipv4);
                arp.set_hw_addr_len(6);
                arp.set_proto_addr_len(4);
                arp.set_operation(ArpOperations::Request);
                arp.set_sender_hw_addr(source_mac);
                arp.set_sender_proto_addr(source_ip);
                arp.set_target_hw_addr(MacAddr(0, 0, 0, 0, 0, 0));
                arp.set_target_proto_addr(*target_ip);
            }

            let mut eth_buf = [0u8; 42];
            {
                let mut eth = MutableEthernetPacket::new(&mut eth_buf).unwrap();
                eth.set_destination(MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
                eth.set_source(source_mac);
                eth.set_ethertype(EtherTypes::Arp);
                eth.set_payload(&arp_buf);
            }
            let _ = tx.send_to(&eth_buf, None);
        }

        // Collect ARP replies for up to 2 seconds
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut results = HashMap::new();

        while std::time::Instant::now() < deadline {
            match rx.next() {
                Ok(packet) => {
                    if let Some(eth) = EthernetPacket::new(packet) {
                        if eth.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp) = ArpPacket::new(eth.payload()) {
                                if arp.get_operation() == ArpOperations::Reply {
                                    results.insert(
                                        arp.get_sender_proto_addr(),
                                        arp.get_sender_hw_addr().to_string(),
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }

        results
    }

    async fn save_arp_results(
        state: &Arc<AppState>,
        results: HashMap<Ipv4Addr, String>,
    ) -> usize {
        let mut count = 0;
        for (ip, mac) in results {
            let ip_str = ip.to_string();
            let hostname = Self::resolve_hostname(&ip_str).await;

            let mut host = match repository::get_host(&state.db, &ip_str).await {
                Ok(Some(existing)) => existing,
                _ => Host::new(ip_str.clone()),
            };

            host.mac_address = Some(mac);
            host.hostname = hostname;
            host.status = HostStatus::Up;
            host.update_last_seen();

            if let Err(e) = repository::upsert_host(&state.db, &host).await {
                tracing::error!("Failed to save host {}: {}", ip_str, e);
            } else {
                let _ = state.broadcaster.send(format!("host_found:{}", ip_str));
                count += 1;
            }
        }
        count
    }

    /// TCP-based host discovery (fallback when ARP is unavailable)
    async fn tcp_discover(ips: &[Ipv4Addr], state: &Arc<AppState>) -> usize {
        let hosts_found = Arc::new(tokio::sync::Mutex::new(0usize));
        let max_threads = std::env::var("MAX_DISCOVER_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(256);
        let sem = Arc::new(Semaphore::new(max_threads));
        let mut futures = FuturesUnordered::new();

        for ip in ips {
            let ip_str = ip.to_string();
            let state_clone = state.clone();
            let hosts_found_clone = hosts_found.clone();
            let sem_clone = sem.clone();

            futures.push(tokio::spawn(async move {
                let _permit = sem_clone.acquire_owned().await.unwrap();
                if Self::is_host_alive(&ip_str).await {
                    let hostname = Self::resolve_hostname(&ip_str).await;

                    let mut host = match repository::get_host(&state_clone.db, &ip_str).await {
                        Ok(Some(existing)) => existing,
                        _ => Host::new(ip_str.clone()),
                    };
                    host.hostname = hostname;
                    host.status = HostStatus::Up;
                    host.update_last_seen();

                    if let Err(e) = repository::upsert_host(&state_clone.db, &host).await {
                        tracing::error!("Failed to save host {}: {}", ip_str, e);
                    } else {
                        let _ = state_clone.broadcaster.send(format!("host_found:{}", ip_str));
                        let mut count = hosts_found_clone.lock().await;
                        *count += 1;
                    }
                }
            }));
        }

        while futures.next().await.is_some() {}
        *hosts_found.lock().await
    }

    /// Reverse DNS lookup for a host IP.
    async fn resolve_hostname(ip: &str) -> Option<String> {
        let addr: IpAddr = ip.parse().ok()?;
        let ip_str = ip.to_string();
        tokio::task::spawn_blocking(move || {
            dns_lookup::lookup_addr(&addr)
                .ok()
                .filter(|h| !h.is_empty() && h != &ip_str)
        })
        .await
        .ok()
        .flatten()
    }

    /// Find the first suitable local network interface and return its details.
    fn detect_local_interface_info() -> Option<(NetworkInterface, Ipv4Addr, MacAddr, Ipv4Net)> {
        for iface in interfaces() {
            if !iface.is_up() || iface.is_loopback() {
                continue;
            }
            if iface.name.starts_with("docker")
                || iface.name.starts_with("veth")
                || iface.name.starts_with("tun")
            {
                continue;
            }
            let mac = match iface.mac {
                Some(m) => m,
                None => continue,
            };
            for ip in &iface.ips {
                if let IpAddr::V4(v4) = ip.ip() {
                    if v4.is_loopback() || v4.is_link_local() {
                        continue;
                    }
                    if let Ok(net) = Ipv4Net::new(v4, ip.prefix()) {
                        return Some((iface, v4, mac, net.trunc()));
                    }
                }
            }
        }
        None
    }

    pub fn detect_local_network() -> Result<IpNet, String> {
        Self::detect_local_interface_info()
            .map(|(_, _, _, net)| IpNet::V4(net))
            .ok_or_else(|| "No suitable local network interface found".to_string())
    }

    async fn is_host_alive(ip: &str) -> bool {
        let ports = [
            80, 443, 8080, 8443,
            22, 23,
            21,
            25, 587,
            445, 139,
            3389,
            3306, 5432,
            6379,
            9100,
            1883, 8883,
            5000, 8888,
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

    fn log_and_broadcast(state: &Arc<AppState>, message: &str) {
        tracing::info!("{}", message);
        let _ = state.broadcaster.send(format!("log:{}", message));
    }
}
