use std::collections::{HashMap, HashSet};
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

pub struct NetworkScanner;

impl NetworkScanner {
    pub async fn discover_hosts(target: &str, job_id: &str, state: &Arc<AppState>) -> Result<usize, String> {
        let network = if target == "self" {
            Self::detect_local_network()?
        } else {
            target
                .parse::<IpNet>()
                .map_err(|_| format!("Invalid network CIDR: {}", target))?
        };

        Self::progress(state, job_id, &format!("Starting discovery on {}", network));

        let ips: Vec<Ipv4Addr> = match &network {
            IpNet::V4(net) => net.hosts().collect(),
            IpNet::V6(_) => return Err("IPv6 scanning not supported".to_string()),
        };

        Self::progress(state, job_id, &format!("Scanning {} IPs", ips.len()));

        // Run ARP and ICMP concurrently — they use independent raw sockets
        let (arp_results, icmp_results) = tokio::join!(
            Self::arp_scan(&ips),
            Self::icmp_scan(&ips)
        );

        // If neither layer-3 method worked, fall back to TCP-only.
        // This most often means the process lacks raw-socket privileges — TCP-only
        // discovery only finds hosts with one of a fixed set of ports open, so it
        // will miss quiet devices. Check the WARN logs from arp_scan/icmp_scan.
        if arp_results.is_empty() && icmp_results.is_empty() {
            Self::progress(state, job_id, "ARP/ICMP returned nothing (missing raw-socket privileges? run with sudo or setcap cap_net_raw+ep) — falling back to limited TCP probe");
            let found = Self::tcp_discover(&ips, job_id, state).await;
            Self::mark_stale_hosts_down(state, &ips, &found).await;
            return Ok(found.len());
        }

        Self::progress(state, job_id, &format!(
            "ARP: {} hosts  ICMP: {} hosts",
            arp_results.len(),
            icmp_results.len()
        ));

        let arp_ips: HashSet<Ipv4Addr> = arp_results.keys().cloned().collect();
        let all_layer3: HashSet<Ipv4Addr> = arp_ips
            .iter()
            .cloned()
            .chain(icmp_results.iter().cloned())
            .collect();

        // Save ARP results first (they carry MAC addresses)
        let mut total = Self::save_arp_results(state, arp_results).await;

        // Save hosts found only by ICMP (no MAC available)
        let icmp_only: Vec<Ipv4Addr> = icmp_results
            .into_iter()
            .filter(|ip| !arp_ips.contains(ip))
            .collect();
        if !icmp_only.is_empty() {
            total += Self::save_hosts_no_mac(state, &icmp_only).await;
        }

        // TCP probe IPs that neither ARP nor ICMP reached
        let remaining: Vec<Ipv4Addr> = ips
            .iter()
            .filter(|ip| !all_layer3.contains(ip))
            .cloned()
            .collect();
        let tcp_found = if !remaining.is_empty() {
            Self::progress(state, job_id, &format!(
                "TCP probing {} IPs not found via ARP/ICMP", remaining.len()
            ));
            Self::tcp_discover(&remaining, job_id, state).await
        } else {
            HashSet::new()
        };
        total += tcp_found.len();

        // Retry pass: ARP/ICMP replies drop intermittently, so before marking any
        // previously-seen host Down, re-probe the missed ones via TCP to avoid flapping.
        let mut all_found: HashSet<Ipv4Addr> = all_layer3.into_iter().chain(tcp_found).collect();
        let recovered = Self::retry_missed_hosts(state, &ips, &all_found).await;
        if !recovered.is_empty() {
            Self::progress(state, job_id, &format!(
                "Recovered {} host(s) via retry probe that ARP/ICMP missed", recovered.len()
            ));
            total += recovered.len();
            all_found.extend(recovered);
        }

        // Mark hosts in this network that weren't found in this scan as Down
        Self::mark_stale_hosts_down(state, &ips, &all_found).await;

        Self::progress(state, job_id, &format!("Discovery complete — {} hosts found", total));
        tracing::info!("Discovery complete. Found {} hosts", total);
        Ok(total)
    }

    /// Re-probe hosts that were previously seen (status Up) in this subnet but were
    /// missed this scan. A quick TCP liveness probe prevents a live host from
    /// flapping to Down when ARP/ICMP drop its replies. Returns the recovered IPs.
    async fn retry_missed_hosts(
        state: &Arc<AppState>,
        scanned_ips: &[Ipv4Addr],
        found: &HashSet<Ipv4Addr>,
    ) -> HashSet<Ipv4Addr> {
        let scanned_set: HashSet<Ipv4Addr> = scanned_ips.iter().cloned().collect();
        let hosts = match repository::list_hosts(&state.db).await {
            Ok(h) => h,
            Err(_) => return HashSet::new(),
        };

        let candidates: Vec<Ipv4Addr> = hosts
            .into_iter()
            .filter_map(|h| {
                if h.status != HostStatus::Up {
                    return None;
                }
                let ip = h.ip.parse::<Ipv4Addr>().ok()?;
                if scanned_set.contains(&ip) && !found.contains(&ip) {
                    Some(ip)
                } else {
                    None
                }
            })
            .collect();

        let mut recovered = HashSet::new();
        for ip in candidates {
            let ip_str = ip.to_string();
            if Self::is_host_alive(&ip_str).await {
                if let Ok(Some(mut host)) = repository::get_host(&state.db, &ip_str).await {
                    host.status = HostStatus::Up;
                    host.update_last_seen();
                    let _ = repository::upsert_host(&state.db, &host).await;
                    let _ = state.broadcaster.send(format!("host_found:{}", ip_str));
                }
                recovered.insert(ip);
            }
        }
        recovered
    }

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
            Ok(_) => {
                tracing::warn!("ARP scan: unexpected channel type on {}", iface.name);
                return HashMap::new();
            }
            Err(e) => {
                tracing::warn!(
                    "ARP scan unavailable on {}: {}. Raw-socket access is required — \
                     run the backend with sudo or grant it `setcap cap_net_raw+ep`. \
                     Falling back to ICMP/TCP discovery.",
                    iface.name, e
                );
                return HashMap::new();
            }
        };

        let send_packet = |tx: &mut Box<dyn pnet_datalink::DataLinkSender>, target_ip: &Ipv4Addr| {
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
        };

        // Interleave sending and receiving so replies to the first probe pass are
        // drained continuously instead of piling up in the NIC ring buffer while we
        // finish transmitting — the previous send-all-then-listen ordering could
        // silently drop replies on a busy /24 and miss hosts.
        // Scale the listen window with the number of targets so large subnets get
        // enough time to collect every reply (a fixed 3s window under-served /23+).
        let start = std::time::Instant::now();
        let listen_ms = (1_500 + targets.len() as u64 * 8).min(15_000);
        let deadline = start + Duration::from_millis(listen_ms);
        let second_pass_at = start + Duration::from_millis(500);
        let mut second_pass_sent = false;
        let mut results = HashMap::new();

        // First pass
        for target_ip in &targets {
            send_packet(&mut tx, target_ip);
        }

        while std::time::Instant::now() < deadline {
            // Second pass after a brief pause — recovers dropped broadcast packets.
            if !second_pass_sent && std::time::Instant::now() >= second_pass_at {
                for target_ip in &targets {
                    send_packet(&mut tx, target_ip);
                }
                second_pass_sent = true;
            }

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
                // A transient read error (e.g. Interrupted) must not abort the whole
                // receive loop — keep draining until the deadline.
                Err(_) => continue,
            }
        }

        results
    }

    async fn icmp_scan(targets: &[Ipv4Addr]) -> HashSet<Ipv4Addr> {
        let targets_owned = targets.to_vec();
        tokio::task::spawn_blocking(move || Self::icmp_scan_blocking(targets_owned))
            .await
            .unwrap_or_default()
    }

    fn icmp_scan_blocking(targets: Vec<Ipv4Addr>) -> HashSet<Ipv4Addr> {
        use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
        use pnet_packet::icmp::{IcmpCode, IcmpTypes};
        use pnet_packet::ip::IpNextHeaderProtocols;
        use pnet_packet::util;
        use pnet_transport::{
            icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
        };

        let (mut tx, mut rx) = match transport_channel(
            65535,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
        ) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "ICMP scan unavailable: {}. Raw-socket access is required — \
                     run the backend with sudo or grant it `setcap cap_net_raw+ep`. \
                     Falling back to TCP discovery.",
                    e
                );
                return HashSet::new();
            }
        };

        let target_set: HashSet<Ipv4Addr> = targets.iter().cloned().collect();

        let send_echo = |tx: &mut pnet_transport::TransportSender, target: &Ipv4Addr| {
            let mut buf = [0u8; 16];
            let mut pkt = MutableEchoRequestPacket::new(&mut buf).unwrap();
            pkt.set_identifier(0xDADA);
            pkt.set_sequence_number(0);
            pkt.set_icmp_type(IcmpTypes::EchoRequest);
            pkt.set_icmp_code(IcmpCode::new(0));
            let cs = util::checksum(pkt.packet(), 1);
            pkt.set_checksum(cs);
            let _ = tx.send_to(pkt, IpAddr::V4(*target));
        };

        // Interleave sending and receiving (same rationale as the ARP path): drain
        // echo replies continuously rather than sending both passes up front and
        // risking dropped replies before the receive loop starts.
        // Adaptive listen window, same rationale as the ARP path.
        let start = std::time::Instant::now();
        let listen_ms = (1_000 + targets.len() as u64 * 6).min(12_000);
        let deadline = start + Duration::from_millis(listen_ms);
        let second_pass_at = start + Duration::from_millis(200);
        let mut second_pass_sent = false;

        // First pass
        for target in &targets {
            send_echo(&mut tx, target);
        }

        let mut found = HashSet::new();
        let mut iter = icmp_packet_iter(&mut rx);

        while std::time::Instant::now() < deadline {
            // Second pass after a brief pause — recovers dropped packets.
            if !second_pass_sent && std::time::Instant::now() >= second_pass_at {
                for target in &targets {
                    send_echo(&mut tx, target);
                }
                second_pass_sent = true;
            }

            match iter.next_with_timeout(Duration::from_millis(100)) {
                Ok(Some((packet, addr))) => {
                    if packet.get_icmp_type() == IcmpTypes::EchoReply {
                        if let IpAddr::V4(v4) = addr {
                            if target_set.contains(&v4) {
                                found.insert(v4);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        found
    }

    async fn save_arp_results(
        state: &Arc<AppState>,
        results: HashMap<Ipv4Addr, String>,
    ) -> usize {
        let mut count = 0;
        for (ip, mac) in results {
            let ip_str = ip.to_string();
            let hostname = Self::resolve_hostname(&ip_str).await;

            // Look up by IP first; if not found, check by MAC to handle DHCP reassignments
            let mut host = match repository::get_host(&state.db, &ip_str).await {
                Ok(Some(existing)) => existing,
                _ => match repository::find_host_by_mac(&state.db, &mac).await {
                    Ok(Some(mut h)) if h.ip != ip_str => {
                        // Known device, IP changed — migrate the record to the new IP
                        tracing::info!("Host {} (MAC {}) moved to {}", h.ip, mac, ip_str);
                        let _ = repository::delete_host(&state.db, &h.ip).await;
                        h.ip = ip_str.clone();
                        h
                    }
                    _ => Host::new(ip_str.clone()),
                },
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

    async fn save_hosts_no_mac(state: &Arc<AppState>, ips: &[Ipv4Addr]) -> usize {
        let mut count = 0;
        for ip in ips {
            let ip_str = ip.to_string();
            let hostname = Self::resolve_hostname(&ip_str).await;
            let mut host = match repository::get_host(&state.db, &ip_str).await {
                Ok(Some(existing)) => existing,
                _ => Host::new(ip_str.clone()),
            };
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

    async fn tcp_discover(ips: &[Ipv4Addr], job_id: &str, state: &Arc<AppState>) -> HashSet<Ipv4Addr> {
        let found: Arc<tokio::sync::Mutex<HashSet<Ipv4Addr>>> =
            Arc::new(tokio::sync::Mutex::new(HashSet::new()));
        let max_threads = crate::settings::current().max_discover_threads;
        let sem = Arc::new(Semaphore::new(max_threads));
        let mut futures = FuturesUnordered::new();

        for ip in ips {
            let ip_addr = *ip;
            let ip_str = ip.to_string();
            let state_clone = state.clone();
            let found_clone = found.clone();
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
                        found_clone.lock().await.insert(ip_addr);
                    }
                }
            }));
        }

        while futures.next().await.is_some() {}
        Arc::try_unwrap(found).unwrap().into_inner()
    }

    async fn mark_stale_hosts_down(
        state: &Arc<AppState>,
        scanned_ips: &[Ipv4Addr],
        found_ips: &HashSet<Ipv4Addr>,
    ) {
        let scanned_set: HashSet<&Ipv4Addr> = scanned_ips.iter().collect();

        let all_hosts = match repository::list_hosts(&state.db).await {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("Failed to list hosts for stale sweep: {}", e);
                return;
            }
        };

        for mut host in all_hosts {
            let Ok(ip) = host.ip.parse::<Ipv4Addr>() else { continue };

            // Mark Down if the host was in the scanned range but not found,
            // OR if the host is from a different subnet entirely (we're on a new network).
            let should_mark_down = if scanned_set.contains(&ip) {
                !found_ips.contains(&ip)
            } else {
                // Host is outside the scanned subnet — we're on a different network now.
                true
            };

            if should_mark_down && host.status != HostStatus::Down {
                host.status = HostStatus::Down;
                if let Err(e) = repository::upsert_host(&state.db, &host).await {
                    tracing::error!("Failed to mark {} as down: {}", host.ip, e);
                } else {
                    tracing::info!("Host {} marked as down (not seen in scan)", host.ip);
                    let _ = state.broadcaster.send(format!("host_down:{}", host.ip));
                }
            }
        }
    }

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

    // Prefer the interface that has the default route — avoids picking a secondary
    // interface (e.g. a disconnected wlan0) when eth0 is the active uplink.
    fn default_route_iface() -> Option<String> {
        let content = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in content.lines().skip(1) {
            let mut fields = line.split_whitespace();
            let iface = fields.next()?;
            let dest = fields.next()?;
            if dest == "00000000" {
                return Some(iface.to_string());
            }
        }
        None
    }

    fn detect_local_interface_info() -> Option<(NetworkInterface, Ipv4Addr, MacAddr, Ipv4Net)> {
        let preferred = Self::default_route_iface();

        let mut candidates: Vec<(NetworkInterface, Ipv4Addr, MacAddr, Ipv4Net)> = Vec::new();

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
            let Some(mac) = iface.mac else { continue };
            for ip in &iface.ips {
                if let IpAddr::V4(v4) = ip.ip() {
                    if v4.is_loopback() || v4.is_link_local() {
                        continue;
                    }
                    if let Ok(net) = Ipv4Net::new(v4, ip.prefix()) {
                        candidates.push((iface.clone(), v4, mac, net.trunc()));
                        break;
                    }
                }
            }
        }

        // Put the default-route interface first
        candidates.sort_by_key(|(iface, _, _, _)| {
            if preferred.as_deref() == Some(iface.name.as_str()) {
                0usize
            } else {
                1
            }
        });

        candidates.into_iter().next()
    }

    pub fn detect_local_network() -> Result<IpNet, String> {
        Self::detect_local_interface_info()
            .map(|(_, _, _, net)| IpNet::V4(net))
            .ok_or_else(|| "No suitable local network interface found".to_string())
    }

    // Returns true as soon as any probe port connects. Drops the remaining
    // futures immediately on first success rather than waiting for all timeouts.
    // The probe port set and per-connection timeout are configurable via settings.
    async fn is_host_alive(ip: &str) -> bool {
        let cfg = crate::settings::current();
        let timeout = Duration::from_millis(cfg.host_alive_timeout_ms);

        let mut futs: FuturesUnordered<_> = cfg
            .fallback_ports
            .iter()
            .map(|&port| {
                let addr = format!("{}:{}", ip, port);
                async move {
                    tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
                        .await
                        .map(|r| r.is_ok())
                        .unwrap_or(false)
                }
            })
            .collect();

        while let Some(alive) = futs.next().await {
            if alive {
                return true; // dropping futs cancels remaining futures
            }
        }
        false
    }

    fn progress(state: &Arc<AppState>, job_id: &str, message: &str) {
        tracing::info!("[discovery {}] {}", job_id, message);
        let _ = state.broadcaster.send(format!("scan_progress:{}:{}", job_id, message));
    }
}
