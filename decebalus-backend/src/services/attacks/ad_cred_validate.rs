//! Validate a single credential against a host over SMB via NetExec, recording
//! whether it authenticates and whether it grants admin (`Pwn3d!`).

use std::sync::Arc;

use serde_json::json;

use crate::db::repository;
use crate::models::Job;
use crate::state::AppState;

use super::nxc_common::{
    active_engagement_id, record_credential, record_fact, require_nxc, run_nxc,
};

pub struct AdCredValidate;

impl AdCredValidate {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object().ok_or("Invalid job config")?;
        let target = job.target()?;
        let username = cfg.get("username").and_then(|v| v.as_str()).ok_or("config.username required")?;
        let password = cfg.get("password").and_then(|v| v.as_str()).unwrap_or("");
        let hash = cfg.get("hash").and_then(|v| v.as_str()).unwrap_or("");
        let domain = cfg.get("domain").and_then(|v| v.as_str()).unwrap_or("");
        if password.is_empty() && hash.is_empty() {
            return Err("config.password or config.hash required".into());
        }
        let bin = require_nxc(state, &job.id, "ad-cred-validate").await?;

        let mut args = vec!["smb".to_string(), target.clone(), "-u".to_string(), username.to_string()];
        if !hash.is_empty() {
            args.push("-H".to_string());
            args.push(hash.to_string());
        } else {
            args.push("-p".to_string());
            args.push(password.to_string());
        }
        if !domain.is_empty() {
            args.push("-d".to_string());
            args.push(domain.to_string());
        }

        let out = run_nxc(bin, &args, 60).await?;
        let (success, admin) = parse_auth(&out.stdout);

        let eng = active_engagement_id(state).await;
        record_fact(state, &eng, &job.id, "host", &target, "valid_cred", json!(success)).await;

        if success {
            let secret = if hash.is_empty() { password } else { hash };
            let secret_type = if hash.is_empty() { "password" } else { "nt_hash" };
            let privilege = if admin { "admin" } else { "user" };
            record_credential(
                state,
                &eng,
                &job.id,
                domain,
                username,
                secret,
                secret_type,
                true,
                vec![format!("{}:smb", target)],
                privilege,
            )
            .await;
        }

        let msg = format!(
            "Credential {}\\{} on {}: {}{}",
            domain,
            username,
            target,
            if success { "VALID" } else { "invalid" },
            if admin { " (admin/Pwn3d!)" } else { "" }
        );
        let _ = repository::add_log(&state.db, "INFO", "attacks", Some("ad-cred-validate"), Some(&job.id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:{}", job.id, msg));

        Ok(json!({ "target": target, "username": username, "valid": success, "admin": admin }).to_string())
    }
}

/// Interpret NetExec SMB auth output: `[+]` ⇒ success, `Pwn3d!` ⇒ admin.
pub fn parse_auth(stdout: &str) -> (bool, bool) {
    let mut success = false;
    let mut admin = false;
    for l in stdout.lines() {
        if l.contains("[+]") {
            success = true;
        }
        if l.contains("Pwn3d!") {
            admin = true;
        }
    }
    (success, admin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_success_and_admin() {
        assert_eq!(parse_auth("SMB 10.0.0.5 445 DC01 [-] acme\\jdoe:pass STATUS_LOGON_FAILURE"), (false, false));
        assert_eq!(parse_auth("SMB 10.0.0.5 445 DC01 [+] acme\\jdoe:pass"), (true, false));
        assert_eq!(parse_auth("SMB 10.0.0.5 445 DC01 [+] acme\\admin:pass (Pwn3d!)"), (true, true));
    }
}
