pub mod ssh_brute;
pub mod ftp_brute;
pub mod file_steal;
pub mod smb_brute;
pub mod rdp_brute;

pub use ssh_brute::SshBruteForce;
pub use ftp_brute::FtpBruteForce;
pub use file_steal::FileSteal;
pub use smb_brute::SmbBruteForce;
pub use rdp_brute::RdpBruteForce;

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use crate::models::Job;
use crate::state::AppState;

/// Metadata describing an attack/exploit module. Exposed via `GET /api/modules`
/// so the frontend can list modules and suggest ones relevant to a host's open ports.
#[derive(Clone, Debug, Serialize)]
pub struct ModuleMeta {
    /// Job-type string used to dispatch this module (e.g. "ssh-brute").
    pub job_type: String,
    /// Human-readable name.
    pub name: String,
    /// "attack" (brute force) or "exfil".
    pub category: String,
    pub description: String,
    /// Config keys the job requires.
    pub required_config: Vec<String>,
    /// Config keys the job optionally accepts.
    pub optional_config: Vec<String>,
    /// Default service port.
    pub default_port: Option<u16>,
    /// Open ports on a host that make this module relevant (for suggestions).
    pub trigger_ports: Vec<u16>,
}

/// A dispatchable attack/exploit module. Implemented by each concrete module and
/// enumerated by [`registry`], replacing the previous hardcoded dispatch match.
#[async_trait]
pub trait AttackModule: Send + Sync {
    fn meta(&self) -> ModuleMeta;
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String>;
}

/// All registered modules. Add a module here to make it dispatchable and listed.
pub fn registry() -> Vec<Box<dyn AttackModule>> {
    vec![
        Box::new(SshBruteForce),
        Box::new(FtpBruteForce),
        Box::new(SmbBruteForce),
        Box::new(RdpBruteForce),
        Box::new(FileSteal),
    ]
}

/// Look up the module handling a given job-type string.
pub fn module_for(job_type: &str) -> Option<Box<dyn AttackModule>> {
    registry().into_iter().find(|m| m.meta().job_type == job_type)
}

/// Metadata for every registered module.
pub fn all_meta() -> Vec<ModuleMeta> {
    registry().iter().map(|m| m.meta()).collect()
}

#[async_trait]
impl AttackModule for SshBruteForce {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ssh-brute".into(),
            name: "SSH Brute Force".into(),
            category: "attack".into(),
            description: "Attempts SSH logins across username/password lists.".into(),
            required_config: vec!["target".into()],
            optional_config: vec!["port".into(), "usernames".into(), "passwords".into(), "concurrency".into()],
            default_port: Some(22),
            trigger_ports: vec![22],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        SshBruteForce::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for FtpBruteForce {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ftp-brute".into(),
            name: "FTP Brute Force".into(),
            category: "attack".into(),
            description: "Attempts FTP logins across username/password lists.".into(),
            required_config: vec!["target".into()],
            optional_config: vec!["port".into(), "usernames".into(), "passwords".into(), "concurrency".into()],
            default_port: Some(21),
            trigger_ports: vec![21],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        FtpBruteForce::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for SmbBruteForce {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "smb-brute".into(),
            name: "SMB Brute Force".into(),
            category: "attack".into(),
            description: "Attempts SMB logins via smbclient across username/password lists.".into(),
            required_config: vec!["target".into()],
            optional_config: vec!["port".into(), "domain".into(), "usernames".into(), "passwords".into(), "concurrency".into()],
            default_port: Some(445),
            trigger_ports: vec![445, 139],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        SmbBruteForce::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for RdpBruteForce {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "rdp-brute".into(),
            name: "RDP Brute Force".into(),
            category: "attack".into(),
            description: "Attempts RDP logins via FreeRDP NLA across username/password lists.".into(),
            required_config: vec!["target".into()],
            optional_config: vec!["port".into(), "domain".into(), "usernames".into(), "passwords".into(), "concurrency".into()],
            default_port: Some(3389),
            trigger_ports: vec![3389],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        RdpBruteForce::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for FileSteal {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "file-steal".into(),
            name: "File Steal (SFTP)".into(),
            category: "exfil".into(),
            description: "Downloads a remote file over SFTP using known credentials.".into(),
            required_config: vec!["target".into(), "username".into(), "password".into(), "remote_path".into()],
            optional_config: vec!["port".into()],
            default_port: Some(22),
            trigger_ports: vec![22],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        FileSteal::run(job, state).await
    }
}

// Pi-specific credential defaults — covers common factory/default credentials.
pub const DEFAULT_USERNAMES: &[&str] = &[
    "root", "pi", "admin", "ubuntu", "user", "raspberry", "test", "guest",
];
pub const DEFAULT_PASSWORDS: &[&str] = &[
    "raspberry", "pi", "admin", "password", "1234", "12345", "root",
    "toor", "pass", "test", "admin123", "default", "letmein", "",
];

/// Load a credential list from the job config. Resolution order:
/// 1. Inline array at `inline_key`
/// 2. File path at `path_key` (one entry per line, # comments stripped)
/// 3. Built-in defaults
pub async fn load_wordlist(
    config: &serde_json::Map<String, Value>,
    inline_key: &str,
    path_key: &str,
    defaults: &[&str],
) -> Vec<String> {
    if let Some(arr) = config.get(inline_key).and_then(|v| v.as_array()) {
        let items: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        if !items.is_empty() {
            return items;
        }
    }

    if let Some(path) = config.get(path_key).and_then(|v| v.as_str()) {
        if let Ok(content) = tokio::fs::read_to_string(path).await {
            let lines: Vec<String> = content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from)
                .collect();
            if !lines.is_empty() {
                return lines;
            }
        }
    }

    defaults.iter().map(|s| s.to_string()).collect()
}
