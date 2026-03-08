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
        let services = Self::detect_services(ip, &open_ports, state, job_id).await;

        // ── Phase 3: persist ─────────────────────────────────────────────────
        let _ = state.broadcaster.send(format!("scan_progress:{}:Saving results for {}", job_id, ip));
        Self::update_host_scan_results(state, ip, &open_ports, &services).await;

        let msg = format!(
            "[port-scan] {} — scan complete: {} open port(s), {} service(s) identified",
            ip, open_ports.len(), services.len()
        );
        tracing::info!("{}", msg);
        let _ = repository::add_log(&state.db, "INFO", "port_scanner", Some("scan_host"), Some(job_id), &msg).await;

        Ok(open_ports.len())
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

    async fn detect_services(ip: &str, open_ports: &[u16], state: &Arc<AppState>, job_id: &str) -> Vec<ServiceInfo> {
        match Self::run_nmap(ip, open_ports, state, job_id).await {
            Ok(services) if !services.is_empty() => {
                let msg = format!(
                    "[port-scan] {} — nmap identified {} service(s)",
                    ip, services.len()
                );
                tracing::info!("{}", msg);
                let _ = repository::add_log(&state.db, "INFO", "port_scanner", Some("nmap"), Some(job_id), &msg).await;
                let _ = state.broadcaster.send(format!(
                    "scan_progress:{}:nmap done — {} service(s) identified on {}",
                    job_id, services.len(), ip
                ));
                services
            }
            Ok(_) => {
                let msg = format!(
                    "[port-scan] {} — nmap returned no services; falling back to banner grabbing",
                    ip
                );
                tracing::warn!("{}", msg);
                let _ = repository::add_log(&state.db, "WARN", "port_scanner", Some("nmap"), Some(job_id), &msg).await;
                let _ = state.broadcaster.send(format!("scan_progress:{}:nmap returned no services for {}, using banner fallback", job_id, ip));
                Self::banner_fallback(ip, open_ports).await
            }
            Err(e) => {
                let msg = format!(
                    "[port-scan] {} — nmap unavailable ({}); falling back to banner grabbing",
                    ip, e
                );
                tracing::warn!("{}", msg);
                let _ = repository::add_log(&state.db, "WARN", "port_scanner", Some("nmap"), Some(job_id), &msg).await;
                let _ = state.broadcaster.send(format!("scan_progress:{}:nmap unavailable for {}, using banner fallback", job_id, ip));
                Self::banner_fallback(ip, open_ports).await
            }
        }
    }

    /// Shell out to nmap for service/version detection on already-confirmed open ports.
    async fn run_nmap(ip: &str, open_ports: &[u16], state: &Arc<AppState>, job_id: &str) -> Result<Vec<ServiceInfo>, String> {
        if open_ports.is_empty() {
            return Ok(vec![]);
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

    /// Parse nmap's XML output (-oX -) and extract per-port service info.
    fn parse_nmap_xml(xml: &str) -> Vec<ServiceInfo> {
        use quick_xml::{Reader, events::Event};

        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut services  = Vec::new();
        let mut cur_port: Option<u16> = None;
        let mut cur_proto = String::from("tcp");

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
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
                            if let Some(port) = cur_port {
                                let mut name       = "unknown".to_string();
                                let mut product    = None;
                                let mut version    = None;
                                let mut extra_info = None;
                                for attr in e.attributes().flatten() {
                                    if let Ok(val) = std::str::from_utf8(&attr.value) {
                                        match attr.key.as_ref() {
                                            b"name"      => name       = val.to_string(),
                                            b"product"   => product    = Some(val.to_string()),
                                            b"version"   => version    = Some(val.to_string()),
                                            b"extrainfo" => extra_info = Some(val.to_string()),
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
                                });
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(ref e)) => {
                    if e.name().as_ref() == b"port" {
                        cur_port = None;
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

        services
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
            });
        }
        result
    }

    // ── Phase 3 ──────────────────────────────────────────────────────────────

    async fn update_host_scan_results(
        state:       &Arc<AppState>,
        ip:          &str,
        open_ports:  &[u16],
        services:    &[ServiceInfo],
    ) {
        let mut host = match repository::get_host(&state.db, ip).await {
            Ok(Some(h)) => h,
            _ => {
                tracing::warn!("Host {} not found in DB during port scan; skipping save", ip);
                return;
            }
        };

        // Ports
        for &port_num in open_ports {
            let protocol = services.iter()
                .find(|s| s.port == port_num)
                .map(|s| s.protocol.as_str())
                .unwrap_or("tcp");
            host.add_port(port_num, protocol, "open");
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

        // OS detection — nmap extrainfo strings work alongside raw SSH banners
        let info_strings: Vec<String> = services.iter()
            .flat_map(|s| [s.extra_info.clone(), s.version.clone()])
            .flatten()
            .collect();
        let (os, os_version) = Self::detect_os(open_ports, &info_strings);
        if os.is_some() {
            host.os         = os;
            host.os_version = os_version;
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
