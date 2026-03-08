use std::sync::Arc;
use std::time::Duration;
use futures_util::StreamExt;
use crate::state::AppState;
use crate::db::repository;
use crate::models::Service;

/// Intermediate type carrying per-port service info from nmap or banner fallback.
struct ServiceInfo {
    port:       u16,
    protocol:   String,
    name:       String,
    product:    Option<String>,
    version:    Option<String>,
    extra_info: Option<String>,
    tunnel:     Option<String>,    // "ssl" when nmap reports tunnel="ssl"
    cpe:        Option<String>,    // first CPE string for this service
}

struct NmapScanResult {
    services:    Vec<ServiceInfo>,
    os_name:     Option<String>,    // e.g. "Linux"
    os_version:  Option<String>,    // e.g. "3.2 - 4.9"
    mac_address: Option<String>,    // e.g. "00:31:92:C1:60:20"
    mac_vendor:  Option<String>,    // e.g. "TP-Link Limited"
    hostname:    Option<String>,    // PTR hostname from nmap
    scripts:     Vec<String>,       // NSE script outputs (port + host level)
    os_cpe:      Option<String>,    // OS CPE from osclass (e.g. "cpe:/o:linux:linux_kernel")
}

/// Extra nmap-derived data passed to update_host_scan_results for nmap-scan jobs.
struct NmapExtra {
    hostname: Option<String>,
    scripts:  Vec<String>,
    os_cpe:   Option<String>,
}

/// Port Scanner Service
///
/// Scanning pipeline:
///   1. Fast concurrent TCP connect scan across all 65 535 ports (200 ms timeout).
///   2. nmap -sV on the confirmed open ports for service/version detection.
///   3. If nmap is unavailable, fall back to banner grabbing + heuristic fingerprinting.
///   4. Persist results and update the host record.
pub struct PortScanner;

impl PortScanner {
    /// Public entry point. Returns the number of open ports found.
    pub async fn scan_host(ip: &str, state: &Arc<AppState>, job_id: &str) -> Result<usize, String> {
        let concurrency = state.max_scan_concurrency;

        let msg = format!(
            "[port-scan] Starting scan on {} | ports: 1-65535 | concurrency: {} | method: TCP connect + nmap -sV fallback",
            ip, concurrency
        );
        tracing::info!("{}", msg);
        let _ = repository::add_log(&state.db, "INFO", "port_scanner", Some("scan_host"), Some(job_id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:TCP scanning {} (ports 1-65535, {} concurrent)", job_id, ip, concurrency));

        // ── Phase 1: fast TCP connect scan ──────────────────────────────────
        let open_ports = Self::tcp_scan_concurrent(ip, concurrency).await;

        if open_ports.is_empty() {
            let msg = format!("[port-scan] {} — TCP scan complete: 0 open ports found", ip);
            tracing::info!("{}", msg);
            let _ = repository::add_log(&state.db, "INFO", "port_scanner", Some("tcp_scan"), Some(job_id), &msg).await;
            let _ = state.broadcaster.send(format!("scan_progress:{}:TCP scan done — 0 open ports on {}", job_id, ip));
            return Ok(0);
        }

        let ports_display = if open_ports.len() <= 30 {
            open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        } else {
            format!(
                "{} ... ({} total)",
                open_ports[..10].iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "),
                open_ports.len()
            )
        };
        let msg = format!(
            "[port-scan] {} — TCP scan complete: {} open port(s) found: [{}]",
            ip, open_ports.len(), ports_display
        );
        tracing::info!("{}", msg);
        let _ = repository::add_log(&state.db, "INFO", "port_scanner", Some("tcp_scan"), Some(job_id), &msg).await;
        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:TCP scan done — {} open port(s) on {}: [{}]",
            job_id, open_ports.len(), ip, ports_display
        ));

        // ── Phase 2: service detection ───────────────────────────────────────
        let (services, os_name, os_version) = Self::detect_services(ip, &open_ports, state, job_id).await;

        // ── Phase 3: persist ─────────────────────────────────────────────────
        let _ = state.broadcaster.send(format!("scan_progress:{}:Saving results for {}", job_id, ip));
        let os_override = if os_name.is_some() {
            Some((os_name, os_version))
        } else {
            None
        };
        Self::update_host_scan_results(state, ip, &open_ports, &services, os_override, None, None).await;

        let msg = format!(
            "[port-scan] {} — scan complete: {} open port(s), {} service(s) identified",
            ip, open_ports.len(), services.len()
        );
        tracing::info!("{}", msg);
        let _ = repository::add_log(&state.db, "INFO", "port_scanner", Some("scan_host"), Some(job_id), &msg).await;

        Ok(open_ports.len())
    }

    /// Full nmap scan entry point for nmap-scan jobs.
    ///
    /// Pipeline:
    ///   1. TCP scan: nmap -sV -O --osscan-guess -p 1-65535 (falls back to no -O if no CAP_NET_RAW)
    ///   2. UDP scan: nmap -sU --top-ports 200 (skipped gracefully if no CAP_NET_RAW)
    ///
    /// Enable both OS detection and UDP scanning without running the backend as root:
    ///   sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)
    ///
    /// Returns the total number of open TCP + UDP ports found.
    pub async fn full_nmap_scan(ip: &str, state: &Arc<AppState>, job_id: &str) -> Result<usize, String> {
        let msg = format!("[nmap-scan] Starting full nmap scan on {}", ip);
        tracing::info!("{}", msg);
        let _ = repository::add_log(&state.db, "INFO", "port_scanner", Some("full_nmap_scan"), Some(job_id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:Full nmap scan starting on {} (TCP all ports + UDP top 200)", job_id, ip));

        // ── TCP scan (with OS detection if capabilities allow) ────────────────
        let NmapScanResult {
            services: tcp_services,
            os_name,
            os_version,
            mac_address,
            mac_vendor,
            hostname,
            scripts,
            os_cpe,
        } = Self::run_full_nmap(ip, state, job_id).await?;
        let tcp_ports: Vec<u16> = tcp_services.iter().map(|s| s.port).collect();

        // ── UDP scan (best-effort, requires CAP_NET_RAW) ──────────────────────
        let udp_result = Self::run_udp_scan(ip, state, job_id).await;
        let udp_ports: Vec<u16> = udp_result.as_ref()
            .map(|r| r.services.iter().map(|s| s.port).collect())
            .unwrap_or_default();

        let total = tcp_ports.len() + udp_ports.len();

        let msg = format!(
            "[nmap-scan] {} — complete: {} TCP + {} UDP open port(s), {} service(s) identified",
            ip, tcp_ports.len(), udp_ports.len(),
            tcp_services.len() + udp_result.as_ref().map(|r| r.services.len()).unwrap_or(0)
        );
        tracing::info!("{}", msg);
        let _ = repository::add_log(&state.db, "INFO", "port_scanner", Some("full_nmap_scan"), Some(job_id), &msg).await;
        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:nmap done — {} TCP + {} UDP port(s) on {}",
            job_id, tcp_ports.len(), udp_ports.len(), ip
        ));

        // ── Persist ───────────────────────────────────────────────────────────
        let _ = state.broadcaster.send(format!("scan_progress:{}:Saving results for {}", job_id, ip));

        let os_override = if os_name.is_some() { Some((os_name, os_version)) } else { None };
        let mac_override = mac_address.map(|mac| (mac, mac_vendor));
        let nmap_extra = if hostname.is_some() || !scripts.is_empty() || os_cpe.is_some() {
            Some(NmapExtra { hostname, scripts, os_cpe })
        } else {
            None
        };
        Self::update_host_scan_results(state, ip, &tcp_ports, &tcp_services, os_override, mac_override, nmap_extra).await;

        if let Some(udp) = udp_result {
            if !udp_ports.is_empty() {
                Self::update_host_scan_results(state, ip, &udp_ports, &udp.services, None, None, None).await;
            }
        }

        Ok(total)
    }

    /// UDP scan against the top 200 most common UDP ports.
    /// Requires root. Invoked via `sudo nmap` — needs NOPASSWD sudoers rule:
    ///   echo "$USER ALL=(root) NOPASSWD: /usr/bin/nmap" | sudo tee /etc/sudoers.d/decebalus-nmap
    /// Returns None gracefully if sudo is not configured or nmap is unavailable.
    async fn run_udp_scan(ip: &str, state: &Arc<AppState>, job_id: &str) -> Option<NmapScanResult> {
        let msg = format!("[nmap-scan] {} — running UDP scan via sudo nmap (top 200 ports)", ip);
        tracing::info!("{}", msg);
        let _ = repository::add_log(&state.db, "INFO", "port_scanner", Some("run_udp_scan"), Some(job_id), &msg).await;
        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:Running UDP scan (top 200 ports) on {}",
            job_id, ip
        ));

        let output = tokio::process::Command::new("sudo")
            .args(["/usr/bin/nmap", "-sU", "--top-ports", "200", "--open",
                   "--max-retries", "1", "--host-timeout", "120s", "-oX", "-", ip])
            .output()
            .await;

        match output {
            Err(e) => {
                let msg = format!("[nmap-scan] {} — UDP scan failed to start: {}", ip, e);
                tracing::warn!("{}", msg);
                let _ = repository::add_log(&state.db, "WARN", "port_scanner", Some("run_udp_scan"), Some(job_id), &msg).await;
                None
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                if out.stdout.is_empty() {
                    let msg = format!(
                        "[nmap-scan] {} — UDP scan skipped (sudo not configured or root required). \
                         To enable: echo \"$USER ALL=(root) NOPASSWD: /usr/bin/nmap\" | sudo tee /etc/sudoers.d/decebalus-nmap",
                        ip
                    );
                    tracing::warn!("{}", msg);
                    let _ = repository::add_log(&state.db, "WARN", "port_scanner", Some("run_udp_scan"), Some(job_id), &msg).await;
                    let _ = state.broadcaster.send(format!(
                        "scan_progress:{}:UDP scan unavailable on {} (sudo not configured)",
                        job_id, ip
                    ));
                    return None;
                }
                if !stderr.trim().is_empty() {
                    tracing::debug!("[nmap-scan] {} — UDP stderr: {}", ip, stderr.trim());
                }
                let result = Self::parse_nmap_xml(&String::from_utf8_lossy(&out.stdout));
                let msg = format!(
                    "[nmap-scan] {} — UDP scan complete: {} open port(s)",
                    ip, result.services.len()
                );
                tracing::info!("{}", msg);
                let _ = repository::add_log(&state.db, "INFO", "port_scanner", Some("run_udp_scan"), Some(job_id), &msg).await;
                let _ = state.broadcaster.send(format!(
                    "scan_progress:{}:UDP done — {} open port(s) on {}",
                    job_id, result.services.len(), ip
                ));
                Some(result)
            }
        }
    }

    // ── Phase 1 ──────────────────────────────────────────────────────────────

    /// Scan all 65 535 TCP ports concurrently, respecting `max_concurrent`.
    async fn tcp_scan_concurrent(ip: &str, max_concurrent: usize) -> Vec<u16> {
        let ip = ip.to_string();

        let mut open_ports: Vec<u16> = futures_util::stream::iter(1u16..=65535)
            .map(|port| {
                let ip = ip.clone();
                async move {
                    if Self::is_port_open(&ip, port).await { Some(port) } else { None }
                }
            })
            .buffer_unordered(max_concurrent)
            .filter_map(|x| async move { x })
            .collect()
            .await;

        open_ports.sort_unstable();
        open_ports
    }

    async fn is_port_open(ip: &str, port: u16) -> bool {
        let addr = format!("{}:{}", ip, port);
        matches!(
            tokio::time::timeout(
                Duration::from_millis(200),
                tokio::net::TcpStream::connect(&addr),
            )
            .await,
            Ok(Ok(_))
        )
    }

    // ── Phase 2 ──────────────────────────────────────────────────────────────

    async fn detect_services(ip: &str, open_ports: &[u16], state: &Arc<AppState>, job_id: &str) -> (Vec<ServiceInfo>, Option<String>, Option<String>) {
        match Self::run_nmap(ip, open_ports, state, job_id).await {
            Ok(result) if !result.services.is_empty() => {
                let svc_count = result.services.len();
                let msg = format!(
                    "[port-scan] {} — nmap identified {} service(s)",
                    ip, svc_count
                );
                tracing::info!("{}", msg);
                let _ = repository::add_log(&state.db, "INFO", "port_scanner", Some("nmap"), Some(job_id), &msg).await;
                let _ = state.broadcaster.send(format!(
                    "scan_progress:{}:nmap done — {} service(s) identified on {}",
                    job_id, svc_count, ip
                ));
                (result.services, result.os_name, result.os_version)
            }
            Ok(_) => {
                let msg = format!(
                    "[port-scan] {} — nmap returned no services; falling back to banner grabbing",
                    ip
                );
                tracing::warn!("{}", msg);
                let _ = repository::add_log(&state.db, "WARN", "port_scanner", Some("nmap"), Some(job_id), &msg).await;
                let _ = state.broadcaster.send(format!("scan_progress:{}:nmap returned no services for {}, using banner fallback", job_id, ip));
                (Self::banner_fallback(ip, open_ports).await, None, None)
            }
            Err(e) => {
                let msg = format!(
                    "[port-scan] {} — nmap unavailable ({}); falling back to banner grabbing",
                    ip, e
                );
                tracing::warn!("{}", msg);
                let _ = repository::add_log(&state.db, "WARN", "port_scanner", Some("nmap"), Some(job_id), &msg).await;
                let _ = state.broadcaster.send(format!("scan_progress:{}:nmap unavailable for {}, using banner fallback", job_id, ip));
                (Self::banner_fallback(ip, open_ports).await, None, None)
            }
        }
    }

    /// Shell out to nmap for service/version detection on already-confirmed open ports.
    async fn run_nmap(ip: &str, open_ports: &[u16], state: &Arc<AppState>, job_id: &str) -> Result<NmapScanResult, String> {
        if open_ports.is_empty() {
            return Ok(NmapScanResult { services: vec![], os_name: None, os_version: None, mac_address: None, mac_vendor: None, hostname: None, scripts: vec![], os_cpe: None });
        }

        let ports_arg = open_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let cmd = format!(
            "nmap -sV --open --max-retries 1 --host-timeout 120s -p {} -oX - {}",
            ports_arg, ip
        );
        let msg = format!("[port-scan] {} — running nmap: `{}`", ip, cmd);
        tracing::info!("{}", msg);
        let _ = repository::add_log(&state.db, "INFO", "port_scanner", Some("nmap"), Some(job_id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:Running nmap -sV on {} port(s) for {}", job_id, open_ports.len(), ip));

        let output = tokio::process::Command::new("nmap")
            .args([
                "-sV",
                "--open",
                "--max-retries", "1",
                "--host-timeout", "120s",
                "-p", &ports_arg,
                "-oX", "-",
                ip,
            ])
            .output()
            .await
            .map_err(|e| format!("nmap not found or failed to start: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("nmap exited with error: {}", stderr.trim()));
        }

        let xml = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_nmap_xml(&xml))
    }

    /// Run a full nmap scan (no pre-TCP scan).
    /// Tries with OS detection (-O) first; automatically falls back to service-only if
    /// raw socket access is unavailable (i.e. not root and no CAP_NET_RAW capability).
    async fn run_full_nmap(ip: &str, state: &Arc<AppState>, job_id: &str) -> Result<NmapScanResult, String> {
        // Attempt 1: with OS detection
        match Self::run_nmap_cmd(ip, true, state, job_id).await {
            Ok(result) => return Ok(result),
            Err(e) if e.contains("CAP_NET_RAW") || e.contains("root") || e.contains("no output") => {
                let msg = format!(
                    "[nmap-scan] {} — OS detection unavailable ({}); retrying without -O. \
                     To enable, add a sudoers rule: \
                     echo \"$USER ALL=(root) NOPASSWD: /usr/bin/nmap\" | sudo tee /etc/sudoers.d/decebalus-nmap",
                    ip, e
                );
                tracing::warn!("{}", msg);
                let _ = repository::add_log(&state.db, "WARN", "port_scanner", Some("run_full_nmap"), Some(job_id), &msg).await;
                let _ = state.broadcaster.send(format!(
                    "scan_progress:{}:OS detection unavailable on {}, continuing with service scan only",
                    job_id, ip
                ));
            }
            Err(e) => return Err(e),
        }

        // Attempt 2: without OS detection
        Self::run_nmap_cmd(ip, false, state, job_id).await
    }

    /// Execute nmap and return parsed results.
    /// `with_os`: include `-O --osscan-guess` flags (requires root).
    /// When `with_os` is true, nmap is invoked via `sudo` so that OS detection works without
    /// running the backend as root. Requires a NOPASSWD sudoers entry for nmap:
    ///   echo "$USER ALL=(root) NOPASSWD: /usr/bin/nmap" | sudo tee /etc/sudoers.d/decebalus-nmap
    async fn run_nmap_cmd(ip: &str, with_os: bool, state: &Arc<AppState>, job_id: &str) -> Result<NmapScanResult, String> {
        let os_flags = if with_os { " -O --osscan-guess" } else { "" };
        let sudo_prefix = if with_os { "sudo " } else { "" };
        let cmd_str = format!(
            "{}nmap -sV{} --open --max-retries 2 --host-timeout 300s -p 1-65535 -oX - {}",
            sudo_prefix, os_flags, ip
        );
        let msg = format!("[nmap-scan] {} — running: `{}`", ip, cmd_str);
        tracing::info!("{}", msg);
        let _ = repository::add_log(&state.db, "INFO", "port_scanner", Some("run_nmap_cmd"), Some(job_id), &msg).await;
        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:Running {}nmap{} on all ports for {} (this may take a few minutes)",
            job_id, sudo_prefix, os_flags, ip
        ));

        let nmap_args = {
            let mut v = vec![
                "-sV",
                "--open",
                "--max-retries", "2",
                "--host-timeout", "300s",
                "-p", "1-65535",
                "-oX", "-",
            ];
            if with_os {
                v.extend(["-O", "--osscan-guess"]);
            }
            v.push(ip);
            v
        };

        // Privileged scans go through sudo so nmap's root check passes without
        // running the entire backend as root.
        let output = if with_os {
            tokio::process::Command::new("sudo")
                .args(std::iter::once("/usr/bin/nmap").chain(nmap_args))
                .output()
                .await
                .map_err(|e| format!("sudo nmap failed to start: {}", e))?
        } else {
            tokio::process::Command::new("nmap")
                .args(&nmap_args)
                .output()
                .await
                .map_err(|e| format!("nmap not found or failed to start: {}", e))?
        };

        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            let msg = format!("[nmap-scan] {} — nmap stderr: {}", ip, stderr.trim());
            tracing::debug!("{}", msg);
            let _ = repository::add_log(&state.db, "DEBUG", "port_scanner", Some("run_nmap_cmd"), Some(job_id), &msg).await;
        }

        if output.stdout.is_empty() {
            // Propagate stderr so the caller can detect root/CAP issues
            return Err(format!("no output: {}", stderr.trim()));
        }

        let xml = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_nmap_xml(&xml))
    }

    /// Parse nmap's XML output (-oX -) and extract per-port service info, OS detection,
    /// hostname, NSE script outputs, and CPE strings.
    fn parse_nmap_xml(xml: &str) -> NmapScanResult {
        use quick_xml::{Reader, events::Event};

        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut services         = Vec::new();
        let mut cur_port: Option<u16> = None;
        let mut cur_proto        = String::from("tcp");
        let mut in_os            = false;
        let mut in_service       = false;   // inside <service> Start (may have <cpe> children)
        let mut in_osclass       = false;   // inside <osclass> (may have <cpe> children)
        let mut collecting_cpe   = false;   // collecting text inside <cpe>
        let mut cpe_buf          = String::new();
        let mut best_os_accuracy: u32 = 0;
        let mut best_os_name: Option<String> = None;
        let mut mac_address: Option<String> = None;
        let mut mac_vendor:  Option<String> = None;
        let mut hostname:    Option<String> = None;
        let mut scripts:     Vec<String>    = Vec::new();
        let mut os_cpe:      Option<String> = None;

        loop {
            match reader.read_event() {
                // ── Start elements (may have children) ───────────────────────
                Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        b"port" => {
                            cur_port  = None;
                            cur_proto = "tcp".to_string();
                            for attr in e.attributes().flatten() {
                                if let Ok(val) = std::str::from_utf8(&attr.value) {
                                    match attr.key.as_ref() {
                                        b"portid"   => cur_port  = val.parse().ok(),
                                        b"protocol" => cur_proto = val.to_string(),
                                        _ => {}
                                    }
                                }
                            }
                        }
                        b"service" => {
                            // <service> as a Start element means it has children (e.g. <cpe>)
                            in_service = true;
                            if let Some(port) = cur_port {
                                let mut name       = "unknown".to_string();
                                let mut product    = None;
                                let mut version    = None;
                                let mut extra_info = None;
                                let mut tunnel     = None;
                                for attr in e.attributes().flatten() {
                                    if let Ok(val) = std::str::from_utf8(&attr.value) {
                                        match attr.key.as_ref() {
                                            b"name"      => name       = val.to_string(),
                                            b"product"   => product    = Some(val.to_string()),
                                            b"version"   => version    = Some(val.to_string()),
                                            b"extrainfo" => extra_info = Some(val.to_string()),
                                            b"tunnel"    => tunnel     = Some(val.to_string()),
                                            _ => {}
                                        }
                                    }
                                }
                                services.push(ServiceInfo {
                                    port,
                                    protocol: cur_proto.clone(),
                                    name,
                                    product,
                                    version,
                                    extra_info,
                                    tunnel,
                                    cpe: None, // filled in when </cpe> is processed
                                });
                            }
                        }
                        b"os" => { in_os = true; }
                        b"osclass" => { in_osclass = true; }
                        b"cpe" => {
                            collecting_cpe = true;
                            cpe_buf.clear();
                        }
                        _ => {}
                    }
                }
                // ── Empty elements (self-closing, no children) ────────────────
                Ok(Event::Empty(ref e)) => {
                    match e.name().as_ref() {
                        b"port" => {
                            cur_port  = None;
                            cur_proto = "tcp".to_string();
                            for attr in e.attributes().flatten() {
                                if let Ok(val) = std::str::from_utf8(&attr.value) {
                                    match attr.key.as_ref() {
                                        b"portid"   => cur_port  = val.parse().ok(),
                                        b"protocol" => cur_proto = val.to_string(),
                                        _ => {}
                                    }
                                }
                            }
                        }
                        b"service" => {
                            // <service/> as Empty element — no CPE children
                            if let Some(port) = cur_port {
                                let mut name       = "unknown".to_string();
                                let mut product    = None;
                                let mut version    = None;
                                let mut extra_info = None;
                                let mut tunnel     = None;
                                for attr in e.attributes().flatten() {
                                    if let Ok(val) = std::str::from_utf8(&attr.value) {
                                        match attr.key.as_ref() {
                                            b"name"      => name       = val.to_string(),
                                            b"product"   => product    = Some(val.to_string()),
                                            b"version"   => version    = Some(val.to_string()),
                                            b"extrainfo" => extra_info = Some(val.to_string()),
                                            b"tunnel"    => tunnel     = Some(val.to_string()),
                                            _ => {}
                                        }
                                    }
                                }
                                services.push(ServiceInfo {
                                    port,
                                    protocol: cur_proto.clone(),
                                    name,
                                    product,
                                    version,
                                    extra_info,
                                    tunnel,
                                    cpe: None,
                                });
                            }
                        }
                        b"address" => {
                            let mut addrtype = String::new();
                            let mut addr     = String::new();
                            let mut vendor   = String::new();
                            for attr in e.attributes().flatten() {
                                if let Ok(val) = std::str::from_utf8(&attr.value) {
                                    match attr.key.as_ref() {
                                        b"addrtype" => addrtype = val.to_string(),
                                        b"addr"     => addr     = val.to_string(),
                                        b"vendor"   => vendor   = val.to_string(),
                                        _ => {}
                                    }
                                }
                            }
                            if addrtype == "mac" && !addr.is_empty() {
                                mac_address = Some(addr);
                                if !vendor.is_empty() {
                                    mac_vendor = Some(vendor);
                                }
                            }
                        }
                        b"osmatch" => {
                            if in_os {
                                let mut name: Option<String> = None;
                                let mut accuracy: u32 = 0;
                                for attr in e.attributes().flatten() {
                                    if let Ok(val) = std::str::from_utf8(&attr.value) {
                                        match attr.key.as_ref() {
                                            b"name"     => name     = Some(val.to_string()),
                                            b"accuracy" => accuracy = val.parse().unwrap_or(0),
                                            _ => {}
                                        }
                                    }
                                }
                                if accuracy > best_os_accuracy {
                                    best_os_accuracy = accuracy;
                                    best_os_name = name;
                                }
                            }
                        }
                        b"hostname" => {
                            // <hostname name="..." type="PTR"/> — take the PTR record
                            let mut name: Option<String> = None;
                            let mut htype = String::new();
                            for attr in e.attributes().flatten() {
                                if let Ok(val) = std::str::from_utf8(&attr.value) {
                                    match attr.key.as_ref() {
                                        b"name" => name  = Some(val.to_string()),
                                        b"type" => htype = val.to_string(),
                                        _ => {}
                                    }
                                }
                            }
                            // Prefer PTR record; fall back to any first hostname
                            if hostname.is_none() || htype == "PTR" {
                                hostname = name;
                            }
                        }
                        b"script" => {
                            // NSE script output — capture "id: output" string
                            let mut id     = String::new();
                            let mut output = String::new();
                            for attr in e.attributes().flatten() {
                                if let Ok(val) = std::str::from_utf8(&attr.value) {
                                    match attr.key.as_ref() {
                                        b"id"     => id     = val.to_string(),
                                        b"output" => output = val.to_string(),
                                        _ => {}
                                    }
                                }
                            }
                            if !id.is_empty() && !output.is_empty() {
                                let entry = format!("[{}] {}", id, output.trim());
                                if !scripts.contains(&entry) {
                                    scripts.push(entry);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                // ── Text content ─────────────────────────────────────────────
                Ok(Event::Text(ref e)) => {
                    if collecting_cpe {
                        if let Ok(text) = std::str::from_utf8(e.as_ref()) {
                            cpe_buf.push_str(text);
                        }
                    }
                }
                // ── End elements ─────────────────────────────────────────────
                Ok(Event::End(ref e)) => {
                    match e.name().as_ref() {
                        b"port" => { cur_port = None; }
                        b"os"   => { in_os = false; }
                        b"service"    => { in_service = false; }
                        b"osclass"    => { in_osclass = false; }
                        b"cpe" => {
                            if collecting_cpe {
                                collecting_cpe = false;
                                let cpe = cpe_buf.trim().to_string();
                                if !cpe.is_empty() {
                                    if in_service {
                                        // Attach to the service we're inside
                                        if let Some(svc) = services.last_mut() {
                                            if svc.cpe.is_none() {
                                                svc.cpe = Some(cpe);
                                            }
                                        }
                                    } else if in_osclass && os_cpe.is_none() {
                                        os_cpe = Some(cpe);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    tracing::warn!("Error parsing nmap XML: {}", e);
                    break;
                }
                _ => {}
            }
        }

        // Parse os_name and os_version from best_os_name by splitting at first space
        let (os_name, os_version) = if let Some(ref full_name) = best_os_name {
            match full_name.split_once(' ') {
                Some((name, ver)) => (Some(name.to_string()), Some(ver.to_string())),
                None => (Some(full_name.clone()), None),
            }
        } else {
            (None, None)
        };

        NmapScanResult { services, os_name, os_version, mac_address, mac_vendor, hostname, scripts, os_cpe }
    }

    /// Fallback when nmap is unavailable: grab raw banners and fingerprint heuristically.
    async fn banner_fallback(ip: &str, open_ports: &[u16]) -> Vec<ServiceInfo> {
        let mut result = Vec::new();
        for &port in open_ports {
            let banner  = Self::grab_banner(ip, port).await.unwrap_or_default();
            let service = if !banner.is_empty() {
                Self::fingerprint_service(port, &banner)
            } else {
                Service { name: Self::infer_protocol(port), version: None, description: None }
            };
            result.push(ServiceInfo {
                port,
                protocol:   "tcp".to_string(),
                name:       service.name,
                product:    None,
                version:    service.version,
                extra_info: service.description,
                tunnel:     None,
                cpe:        None,
            });
        }
        result
    }

    /// Map a plain service name to its SSL/TLS variant when nmap reports tunnel="ssl".
    fn ssl_service_name(name: &str) -> String {
        match name {
            "http"   => "https".to_string(),
            "ftp"    => "ftps".to_string(),
            "imap"   => "imaps".to_string(),
            "pop3"   => "pop3s".to_string(),
            "smtp"   => "smtps".to_string(),
            "ldap"   => "ldaps".to_string(),
            "telnet" => "telnets".to_string(),
            other    => other.to_string(),
        }
    }

    // ── Phase 3 ──────────────────────────────────────────────────────────────

    async fn update_host_scan_results(
        state:       &Arc<AppState>,
        ip:          &str,
        open_ports:  &[u16],
        services:    &[ServiceInfo],
        os_override:  Option<(Option<String>, Option<String>)>,
        mac_override: Option<(String, Option<String>)>,  // (mac_address, vendor)
        nmap_extra:   Option<NmapExtra>,
    ) {
        let mut host = match repository::get_host(&state.db, ip).await {
            Ok(Some(h)) => h,
            _ => {
                tracing::warn!("Host {} not found in DB during port scan; skipping save", ip);
                return;
            }
        };

        // Ports — pass service name, version, and CPE per port.
        // Apply SSL tunnel service name correction (http→https, ftp→ftps, etc.).
        for &port_num in open_ports {
            let svc_info = services.iter().find(|s| s.port == port_num);
            let protocol = svc_info.map(|s| s.protocol.as_str()).unwrap_or("tcp");
            let service_name = svc_info.map(|s| {
                // Correct service name when nmap reports SSL tunnel
                if s.tunnel.as_deref() == Some("ssl") {
                    Self::ssl_service_name(&s.name)
                } else {
                    s.name.clone()
                }
            });
            let version_str = svc_info.and_then(|s| match (&s.product, &s.version) {
                (Some(p), Some(v)) => Some(format!("{} {}", p, v)),
                (Some(p), None)    => Some(p.clone()),
                (None, Some(v))    => Some(v.clone()),
                (None, None)       => None,
            });
            let cpe = svc_info.and_then(|s| s.cpe.clone());
            host.add_port(port_num, protocol, "open", service_name, version_str, cpe);
        }

        // Services
        for svc in services {
            let version_str = match (&svc.product, &svc.version) {
                (Some(p), Some(v)) => Some(format!("{} {}", p, v)),
                (Some(p), None)    => Some(p.clone()),
                (None, Some(v))    => Some(v.clone()),
                (None, None)       => None,
            };
            let service = Service {
                name:        svc.name.clone(),
                version:     version_str,
                description: svc.extra_info.clone(),
            };
            if !host.services.iter().any(|s| s.name == service.name) {
                host.services.push(service);
            }

            // Store a human-readable banner from the service info
            let parts: Vec<&str> = [
                Some(svc.name.as_str()),
                svc.product.as_deref(),
                svc.version.as_deref(),
                svc.extra_info.as_deref(),
            ]
            .iter()
            .filter_map(|x| *x)
            .collect();
            if !parts.is_empty() {
                host.add_banner(parts.join(" "));
            }
        }

        // OS detection — use nmap override if available, otherwise fall back to heuristics
        if let Some((name, ver)) = os_override {
            if name.is_some() {
                host.os         = name;
                host.os_version = ver;
            }
        } else {
            let info_strings: Vec<String> = services.iter()
                .flat_map(|s| [s.extra_info.clone(), s.version.clone()])
                .flatten()
                .collect();
            let (os, os_version) = Self::detect_os(open_ports, &info_strings);
            if os.is_some() {
                host.os         = os;
                host.os_version = os_version;
            }
        }

        // MAC address — only set if not already known (discovery may have found it first)
        if host.mac_address.is_none() {
            if let Some((mac, vendor)) = mac_override {
                host.mac_address = Some(mac);
                // Store vendor in device_type if not already set
                if host.device_type.is_none() {
                    host.device_type = vendor;
                }
            }
        }

        // NmapExtra — hostname, NSE scripts, OS CPE
        if let Some(extra) = nmap_extra {
            // Hostname: only set if not already known
            if host.hostname.is_none() {
                host.hostname = extra.hostname;
            }
            // NSE script outputs → banners
            for script in extra.scripts {
                host.add_banner(script);
            }
            // OS CPE → banner (informational)
            if let Some(cpe) = extra.os_cpe {
                host.add_banner(format!("[OS CPE] {}", cpe));
            }
        }

        host.update_last_seen();

        if let Err(e) = repository::upsert_host(&state.db, &host).await {
            tracing::error!("Failed to update scan results for {}: {}", ip, e);
        }
    }

    // ── Service fingerprinting (banner fallback) ──────────────────────────────

    fn fingerprint_service(port: u16, banner: &str) -> Service {
        if banner.starts_with("SSH-") {
            return Self::parse_ssh_banner(banner);
        }
        if banner.contains("HTTP/") || banner.to_lowercase().contains("\nserver:") {
            return Self::parse_http_banner(port, banner);
        }
        if banner.starts_with("220 ") || banner.starts_with("220-") {
            return Self::parse_220_banner(port, banner);
        }
        if banner.starts_with("+OK") {
            let description = banner.lines().next().map(|l| l.trim().to_string());
            return Service { name: "pop3".to_string(), version: None, description };
        }
        if banner.starts_with("* OK") {
            let description = banner.lines().next().map(|l| l.trim().to_string());
            return Service { name: "imap".to_string(), version: None, description };
        }
        if banner.starts_with("+PONG") || banner.starts_with("-ERR") {
            return Service { name: "redis".to_string(), version: None, description: None };
        }
        let description = banner.lines().next().map(|l| l.trim().to_string()).filter(|l| !l.is_empty());
        Service { name: Self::infer_protocol(port), version: None, description }
    }

    fn parse_ssh_banner(banner: &str) -> Service {
        let first_line  = banner.lines().next().unwrap_or(banner);
        let after_prefix = first_line.splitn(3, '-').nth(2).unwrap_or(first_line);
        let (software, comment) = match after_prefix.split_once(' ') {
            Some((s, c)) => (s, Some(c.trim())),
            None         => (after_prefix, None),
        };
        Service {
            name:        "ssh".to_string(),
            version:     Some(software.replace('_', " ")),
            description: comment.filter(|s| !s.is_empty()).map(|s| s.to_string()),
        }
    }

    fn parse_http_banner(port: u16, banner: &str) -> Service {
        let name = if port == 443 || port == 8443 { "https" } else { "http" };
        let mut server = None;
        let mut status = None;
        for line in banner.lines() {
            if line.starts_with("HTTP/") && status.is_none() {
                status = line.split_whitespace().skip(1).collect::<Vec<_>>().join(" ").into();
            }
            let lower = line.to_lowercase();
            if lower.starts_with("server:") && server.is_none() {
                server = Some(line[7..].trim().to_string());
            }
        }
        Service { name: name.to_string(), version: server, description: status }
    }

    fn parse_220_banner(port: u16, banner: &str) -> Service {
        let name = match port {
            21           => "ftp".to_string(),
            25 | 465 | 587 => "smtp".to_string(),
            _            => Self::infer_protocol(port),
        };
        let content: Vec<&str> = banner
            .lines()
            .filter(|l| l.starts_with("220"))
            .map(|l| l.trim_start_matches("220").trim_start_matches('-').trim())
            .filter(|l| !l.is_empty())
            .collect();
        let description = if content.is_empty() { None } else { Some(content.join(" ")) };
        Service { name, version: None, description }
    }

    // ── OS detection ─────────────────────────────────────────────────────────

    /// Heuristic OS detection from open ports and service info strings.
    /// Accepts both raw SSH banners ("SSH-2.0-OpenSSH_9.1 Ubuntu-3")
    /// and nmap extrainfo strings ("Ubuntu Linux; protocol 2.0").
    fn detect_os(open_ports: &[u16], info: &[String]) -> (Option<String>, Option<String>) {
        let combined = info.join("\n").to_lowercase();

        // Direct OS mentions (nmap extrainfo)
        if combined.contains("ubuntu") {
            return (Some("Linux".to_string()), Some("Ubuntu".to_string()));
        }
        if combined.contains("debian") {
            return (Some("Linux".to_string()), Some("Debian".to_string()));
        }
        if combined.contains("freebsd") {
            return (Some("FreeBSD".to_string()), None);
        }

        // Raw SSH banner parsing
        for banner in info {
            if banner.starts_with("SSH-") {
                let first   = banner.lines().next().unwrap_or("");
                let comment = first
                    .splitn(3, '-')
                    .nth(2)
                    .and_then(|s| s.split_once(' ').map(|(_, c)| c))
                    .unwrap_or("")
                    .to_lowercase();
                if comment.contains("ubuntu") {
                    return (Some("Linux".to_string()), Some("Ubuntu".to_string()));
                }
                if comment.contains("debian") {
                    return (Some("Linux".to_string()), Some("Debian".to_string()));
                }
                if comment.contains("freebsd") {
                    return (Some("FreeBSD".to_string()), None);
                }
                if !comment.is_empty() {
                    return (Some("Linux".to_string()), None);
                }
            }
        }

        // HTTP Server header
        if combined.contains("iis") || combined.contains("microsoft") {
            return (Some("Windows".to_string()), None);
        }

        // Port-based heuristics
        if open_ports.contains(&3389) || open_ports.contains(&445) || open_ports.contains(&139) {
            return (Some("Windows".to_string()), None);
        }
        if open_ports.contains(&22) || open_ports.contains(&80) || open_ports.contains(&443) {
            return (Some("Linux".to_string()), None);
        }

        (None, None)
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn infer_protocol(port: u16) -> String {
        match port {
            80 | 8080 | 8000 => "http".to_string(),
            443 | 8443        => "https".to_string(),
            22                => "ssh".to_string(),
            21 | 20           => "ftp".to_string(),
            25 | 465 | 587    => "smtp".to_string(),
            110 | 995         => "pop3".to_string(),
            143 | 993         => "imap".to_string(),
            3306              => "mysql".to_string(),
            5432              => "postgresql".to_string(),
            1433              => "mssql".to_string(),
            27017             => "mongodb".to_string(),
            139 | 445 | 135   => "smb".to_string(),
            3389              => "rdp".to_string(),
            53                => "dns".to_string(),
            161               => "snmp".to_string(),
            1521              => "oracle".to_string(),
            6379              => "redis".to_string(),
            9200              => "elasticsearch".to_string(),
            _                 => "unknown".to_string(),
        }
    }

    fn clean_banner(banner: &str) -> String {
        banner
            .lines()
            .take_while(|line| {
                let total = line.chars().count();
                if total == 0 { return true; }
                let bad = line.chars().filter(|c| {
                    *c == '\u{FFFD}' || (*c as u32) < 0x20 && *c != '\t'
                }).count();
                (bad as f64 / total as f64) < 0.15
            })
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    }

    async fn grab_banner(ip: &str, port: u16) -> Option<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let addr = format!("{}:{}", ip, port);

        match tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream = tokio::net::TcpStream::connect(&addr).await?;

            if [80, 8080, 8000, 443].contains(&port) {
                let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
            } else if port == 21 {
                let _ = stream.write_all(b"HELP\r\n").await;
            } else if port == 6379 {
                let _ = stream.write_all(b"PING\r\n").await;
            }

            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await?;
            if n > 0 {
                let raw = String::from_utf8_lossy(&buf[..n])
                    .replace('\r', "")
                    .trim_end()
                    .to_string();
                return Ok(Some(raw));
            }
            Ok::<Option<String>, std::io::Error>(None)
        })
        .await
        {
            Ok(Ok(Some(banner))) if !banner.is_empty() => {
                let clean = Self::clean_banner(&banner);
                if clean.is_empty() { None } else { Some(clean) }
            }
            _ => None,
        }
    }
}
