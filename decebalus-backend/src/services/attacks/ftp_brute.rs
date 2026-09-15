use std::sync::Arc;
use std::time::Duration;
use futures_util::StreamExt;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use crate::models::Job;
use crate::state::AppState;
use crate::db::repository;
use super::{clamp_concurrency, credential_pairs, DEFAULT_PASSWORDS, DEFAULT_USERNAMES, load_wordlist};

pub struct FtpBruteForce;

impl FtpBruteForce {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object()
            .ok_or("Invalid job config")?;

        let target = cfg["target"].as_str().ok_or("Missing target")?;
        let port = cfg.get("port").and_then(|v| v.as_u64()).unwrap_or(21) as u16;
        let concurrency = clamp_concurrency(cfg.get("concurrency").and_then(|v| v.as_u64()).unwrap_or(20) as usize);

        let usernames = Arc::new(load_wordlist(&state.db, cfg, "usernames_wordlist_id", "usernames", "usernames_path", DEFAULT_USERNAMES).await);
        let passwords = Arc::new(load_wordlist(&state.db, cfg, "passwords_wordlist_id", "passwords", "wordlist_path", DEFAULT_PASSWORDS).await);

        let total = usernames.len() * passwords.len();
        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:FTP brute — {} usernames × {} passwords = {} attempts on {}:{}",
            job.id, usernames.len(), passwords.len(), total, target, port
        ));

        let target = Arc::new(target.to_string());
        let mut attempts_stream = credential_pairs(usernames, passwords)
            .map(|(username, password)| {
                let target = target.clone();
                async move {
                    let result = try_ftp_login(&target, port, &username, &password).await;
                    (username, password, result)
                }
            })
            .buffer_unordered(concurrency);

        let mut found: Vec<String> = Vec::new();
        let mut attempted: usize = 0;

        while let Some((user, pass, result)) = attempts_stream.next().await {
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
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .map_err(|_| "read timeout".to_string())?
            .map_err(|e| e.to_string())?;

        if n == 0 {
            return Err("connection closed".to_string());
        }

        // Multi-line response: `NNN-text` continues until `NNN text` (space after code).
        if line.len() >= 4 && line.as_bytes()[3] == b'-' {
            continue;
        }
        return Ok(line); // final status line
    }
}
