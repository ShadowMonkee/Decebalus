use std::sync::Arc;
use std::time::Duration;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use crate::models::Job;
use crate::state::AppState;
use crate::db::repository;
use super::{DEFAULT_PASSWORDS, DEFAULT_USERNAMES, load_wordlist};

pub struct FtpBruteForce;

impl FtpBruteForce {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object()
            .ok_or("Invalid job config")?;

        let target = cfg["target"].as_str().ok_or("Missing target")?;
        let port = cfg.get("port").and_then(|v| v.as_u64()).unwrap_or(21) as u16;
        let concurrency = cfg.get("concurrency").and_then(|v| v.as_u64()).unwrap_or(3) as usize;

        let usernames = load_wordlist(cfg, "usernames", "usernames_path", DEFAULT_USERNAMES).await;
        let passwords = load_wordlist(cfg, "passwords", "wordlist_path", DEFAULT_PASSWORDS).await;

        let total = usernames.len() * passwords.len();
        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:FTP brute — {} usernames × {} passwords = {} attempts on {}:{}",
            job.id, usernames.len(), passwords.len(), total, target, port
        ));

        let sem = Arc::new(Semaphore::new(concurrency));
        let mut futs = FuturesUnordered::new();

        for username in &usernames {
            for password in &passwords {
                let target = target.to_string();
                let username = username.clone();
                let password = password.clone();
                let sem = sem.clone();

                futs.push(async move {
                    let _permit = sem.acquire_owned().await.unwrap();
                    let result = try_ftp_login(&target, port, &username, &password).await;
                    (username, password, result)
                });
            }
        }

        let mut found: Vec<String> = Vec::new();
        let mut attempted: usize = 0;

        while let Some((user, pass, result)) = futs.next().await {
            attempted += 1;

            // Broadcast progress every 20 attempts
            if attempted % 20 == 0 {
                let _ = state.broadcaster.send(format!(
                    "scan_progress:{}:{}/{} attempts ({} found)",
                    job.id, attempted, total, found.len()
                ));
            }

            // Check for cancellation every 10 attempts
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
                    tracing::debug!("[ftp-brute] {}:{} → {}", user, pass, e);
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

/// Attempt a single FTP login. Returns Ok(true) on success, Ok(false) on auth failure.
async fn try_ftp_login(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<bool, String> {
    let addr = format!("{}:{}", host, port);

    let stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Read and consume the server banner (may be multi-line)
    read_ftp_response(&mut reader).await?;

    // Send USER
    write_half
        .write_all(format!("USER {}\r\n", username).as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let user_resp = read_ftp_response(&mut reader).await?;

    if user_resp.starts_with("230") {
        // Logged in without a password
        return Ok(true);
    }
    if !user_resp.starts_with("331") {
        // Anything other than "password required" means this user can't log in
        return Ok(false);
    }

    // Send PASS
    write_half
        .write_all(format!("PASS {}\r\n", password).as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let pass_resp = read_ftp_response(&mut reader).await?;
    Ok(pass_resp.starts_with("230"))
}

/// Read a complete FTP response (handles multi-line `NNN-...\r\nNNN ...\r\n`).
/// Returns the final status line.
async fn read_ftp_response<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Result<String, String> {
    let mut last_line = String::new();
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .map_err(|_| "read timeout".to_string())?
            .map_err(|e| e.to_string())?;

        if n == 0 {
            return Err("connection closed".to_string());
        }

        last_line = line.clone();

        // Multi-line response: `NNN-text` continues until `NNN text` (space after code)
        if line.len() >= 4 && line.as_bytes()[3] == b'-' {
            continue;
        }
        break;
    }
    Ok(last_line)
}
