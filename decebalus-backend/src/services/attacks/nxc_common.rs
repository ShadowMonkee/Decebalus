//! Shared helpers for the AD modules that wrap NetExec (`nxc`).
//!
//! These follow the same shell-out-and-parse pattern as `smb_brute`/`rdp_brute`:
//! probe for the binary, run it under a timeout, and parse stdout. Parsing lives
//! in the individual modules so it stays pure and unit-testable against canned
//! `nxc` output (no live AD required).

use std::process::Stdio;
use std::sync::Arc;

use serde_json::{Map, Value};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::db::repository;
use crate::models::{Credential, Fact, Finding};
use crate::state::AppState;

/// Captured result of an `nxc` invocation.
pub struct NxcOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Resolve the NetExec binary name on PATH. NetExec ships as `nxc`; older
/// installs expose `netexec`. Returns the first that responds to `--version`.
pub async fn nxc_binary() -> Option<&'static str> {
    for bin in ["nxc", "netexec"] {
        let ok = Command::new(bin)
            .arg("--version")
            .stdin(Stdio::null())
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Some(bin);
        }
    }
    None
}

/// Run any external tool with a timeout, capturing stdout/stderr. In OPSEC quiet
/// mode a jittered delay is applied first to space out network-touching commands.
pub async fn run_tool(bin: &str, args: &[String], timeout_secs: u64) -> Result<NxcOutput, String> {
    let s = crate::settings::current();
    if s.opsec_quiet && s.opsec_jitter_ms > 0 {
        // Cheap time-derived jitter in [0, opsec_jitter_ms) — no extra dependency.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
        let delay = nanos % s.opsec_jitter_ms;
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }

    let output = timeout(
        Duration::from_secs(timeout_secs),
        Command::new(bin).args(args).stdin(Stdio::null()).output(),
    )
    .await
    .map_err(|_| format!("{} timed out after {}s", bin, timeout_secs))?
    .map_err(|e| format!("failed to run {}: {}", bin, e))?;

    Ok(NxcOutput {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

/// Run `nxc <args>` with a timeout, capturing stdout/stderr.
pub async fn run_nxc(bin: &str, args: &[String], timeout_secs: u64) -> Result<NxcOutput, String> {
    run_tool(bin, args, timeout_secs).await
}

/// Credentials pulled from a job config. Empty username+password ⇒ a null session.
pub struct Creds {
    pub username: String,
    pub password: String,
    pub domain: String,
}

/// Extract username/password/domain from a job config (all optional).
pub fn creds_from_config(cfg: &Map<String, Value>) -> Creds {
    let s = |k: &str| cfg.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    Creds {
        username: s("username"),
        password: s("password"),
        domain: s("domain"),
    }
}

impl Creds {
    /// True when no username was supplied — i.e. an anonymous/null session attempt.
    pub fn is_null_session(&self) -> bool {
        self.username.is_empty()
    }

    /// The `-u/-p[/-d]` arguments for nxc. Empty user/pass drive a null session.
    pub fn auth_args(&self) -> Vec<String> {
        let mut a = vec![
            "-u".to_string(),
            self.username.clone(),
            "-p".to_string(),
            self.password.clone(),
        ];
        if !self.domain.is_empty() {
            a.push("-d".to_string());
            a.push(self.domain.clone());
        }
        a
    }
}

/// The active engagement's id, or "" (the implicit global engagement) if none.
pub async fn active_engagement_id(state: &Arc<AppState>) -> String {
    repository::get_active_engagement(&state.db)
        .await
        .ok()
        .flatten()
        .map(|e| e.id)
        .unwrap_or_default()
}

/// Record (upsert) a single fact tied to the active engagement and source job.
pub async fn record_fact(
    state: &Arc<AppState>,
    engagement_id: &str,
    job_id: &str,
    subject_type: &str,
    subject_id: &str,
    key: &str,
    value: Value,
) {
    let mut f = Fact::new(subject_type, subject_id, key, value);
    f.engagement_id = engagement_id.to_string();
    f.source_job_id = Some(job_id.to_string());
    let _ = repository::upsert_fact(&state.db, &f).await;
}

/// Standard fail-fast when NetExec isn't installed: logs a helpful hint and
/// returns the error string modules should propagate.
pub async fn require_nxc(state: &Arc<AppState>, job_id: &str, module: &str) -> Result<&'static str, String> {
    match nxc_binary().await {
        Some(bin) => Ok(bin),
        None => {
            let msg = "NetExec (nxc) not found — install it to run AD modules \
                       (pipx install netexec, or see netexec.wiki).";
            let _ = repository::add_log(&state.db, "ERROR", "attacks", Some(module), Some(job_id), msg).await;
            Err(msg.to_string())
        }
    }
}

/// True if `name` responds to `--version` on PATH (used to probe certipy, etc.).
pub async fn binary_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Fail-fast requiring an arbitrary external binary; logs an install hint.
pub async fn require_binary(
    state: &Arc<AppState>,
    job_id: &str,
    module: &str,
    name: &str,
    hint: &str,
) -> Result<(), String> {
    if binary_available(name).await {
        return Ok(());
    }
    let msg = format!("{} not found — {}", name, hint);
    let _ = repository::add_log(&state.db, "ERROR", "attacks", Some(module), Some(job_id), &msg).await;
    Err(msg)
}

/// Upsert a finding and announce it (legacy string + structured event).
pub async fn record_finding(state: &Arc<AppState>, f: &Finding) {
    let _ = repository::upsert_finding(&state.db, f).await;
    let _ = state.broadcaster.send(format!("finding_new:{}", f.title));
    crate::services::events::emit(state, "finding", serde_json::to_value(f).unwrap_or_default());
}

/// Store a discovered credential and announce validated ones.
#[allow(clippy::too_many_arguments)]
pub async fn record_credential(
    state: &Arc<AppState>,
    engagement_id: &str,
    job_id: &str,
    domain: &str,
    username: &str,
    secret: &str,
    secret_type: &str,
    validated: bool,
    valid_on: Vec<String>,
    privilege: &str,
) {
    let mut c = Credential::new(username.to_string(), secret.to_string());
    c.engagement_id = engagement_id.to_string();
    c.domain = domain.to_string();
    c.secret_type = secret_type.to_string();
    c.source_job_id = Some(job_id.to_string());
    c.validated = validated;
    c.valid_on = valid_on;
    c.privilege = privilege.to_string();
    let _ = repository::add_credential(&state.db, &c).await;
    if validated {
        let _ = state.broadcaster.send(format!("cred_found:{}\\{}", domain, username));
    }
    crate::services::events::emit(
        state,
        "cred",
        serde_json::json!({
            "domain": domain,
            "username": username,
            "privilege": privilege,
            "validated": validated,
        }),
    );
}

/// Write loot bytes under the loot dir (default `data/loot`), returning the path.
pub async fn save_loot(target: &str, label: &str, content: &[u8]) -> std::io::Result<String> {
    let dir = std::env::var("LOOT_DIR").unwrap_or_else(|_| "data/loot".to_string());
    tokio::fs::create_dir_all(&dir).await?;
    let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let safe: String = label
        .chars()
        .map(|c| if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect();
    let path = format!("{}/{}_{}_{}", dir, target, ts, safe);
    tokio::fs::write(&path, content).await?;
    Ok(path)
}
