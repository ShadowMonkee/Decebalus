//! Read-only anonymous (null-session) SMB enumeration via NetExec.
//!
//! Runs `nxc smb <target> -u '' -p '' --users --shares` and records whether the
//! null session was accepted, the enumerated users (spray candidates), and the
//! shares (readable SYSVOL/NETLOGON ⇒ GPP hunting). `parse_shares` is reused by
//! the share-hunt module.

use std::sync::Arc;

use serde_json::json;

use crate::db::repository;
use crate::models::Job;
use crate::state::AppState;

use super::nxc_common::{active_engagement_id, record_fact, require_nxc, run_nxc};

pub struct AdNullSession;

/// One SMB share and the access the current session has to it.
#[derive(Debug, Clone, PartialEq)]
pub struct ShareInfo {
    pub name: String,
    pub readable: bool,
    pub writable: bool,
}

impl AdNullSession {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let _cfg = job.config.as_object().ok_or("Invalid job config")?;
        let target = job.target()?;
        let bin = require_nxc(state, &job.id, "ad-null-session").await?;

        let args = vec![
            "smb".to_string(),
            target.clone(),
            "-u".to_string(),
            String::new(),
            "-p".to_string(),
            String::new(),
            "--users".to_string(),
            "--shares".to_string(),
        ];

        let _ = state
            .broadcaster
            .send(format!("scan_progress:{}:Null-session enum on {}", job.id, target));

        let out = run_nxc(bin, &args, 240).await?;
        let allowed = null_session_allowed(&out.stdout);
        let users = parse_users(&out.stdout);
        let shares = parse_shares(&out.stdout);
        let readable: Vec<String> = shares.iter().filter(|s| s.readable).map(|s| s.name.clone()).collect();

        let eng = active_engagement_id(state).await;
        record_fact(state, &eng, &job.id, "host", &target, "null_session", json!(allowed)).await;
        if !users.is_empty() {
            record_fact(state, &eng, &job.id, "host", &target, "users", json!(users)).await;
        }
        if !shares.is_empty() {
            let names: Vec<&String> = shares.iter().map(|s| &s.name).collect();
            record_fact(state, &eng, &job.id, "host", &target, "shares", json!(names)).await;
            record_fact(state, &eng, &job.id, "host", &target, "readable_shares", json!(readable)).await;
        }

        let msg = format!(
            "Null session {} on {}: {} user(s), {} share(s) ({} readable)",
            if allowed { "ALLOWED" } else { "denied" },
            target,
            users.len(),
            shares.len(),
            readable.len()
        );
        let _ = repository::add_log(&state.db, "INFO", "attacks", Some("ad-null-session"), Some(&job.id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:{}", job.id, msg));

        Ok(json!({
            "target": target,
            "null_session": allowed,
            "users": users,
            "readable_shares": readable,
            "shares": shares.iter().map(|s| json!({
                "name": s.name, "readable": s.readable, "writable": s.writable
            })).collect::<Vec<_>>(),
        })
        .to_string())
    }
}

/// True if any line indicates an accepted (anonymous) authentication.
pub fn null_session_allowed(stdout: &str) -> bool {
    stdout.lines().any(|l| l.contains("[+]"))
}

/// Extract `domain\username` entries from `nxc --users` output.
pub fn parse_users(stdout: &str) -> Vec<String> {
    let mut users = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("SMB") {
            continue;
        }
        for tok in trimmed.split_whitespace() {
            if let Some((_, user)) = tok.split_once('\\') {
                let user = user.trim();
                if user.is_empty() || user.starts_with('-') || user.contains(':') {
                    continue;
                }
                if !users.iter().any(|u: &String| u.eq_ignore_ascii_case(user)) {
                    users.push(user.to_string());
                }
            }
        }
    }
    users
}

/// Parse the share table from `nxc --shares` output. Readable/writable are
/// derived from the Permissions column (READ / WRITE) to tolerate remark spacing.
pub fn parse_shares(stdout: &str) -> Vec<ShareInfo> {
    let mut shares = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("SMB") {
            continue;
        }
        // Skip header/separator rows.
        if trimmed.contains("Share") && trimmed.contains("Permissions") {
            continue;
        }
        if trimmed.contains("-----") {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        // SMB <ip> <port> <name> <Share> ...
        let Some(name) = tokens.get(4) else { continue };
        if name.starts_with('[') {
            continue; // status line, not a share row
        }
        let upper = trimmed.to_ascii_uppercase();
        shares.push(ShareInfo {
            name: name.to_string(),
            readable: upper.contains("READ"),
            writable: upper.contains("WRITE"),
        });
    }
    shares
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARES: &str = "\
SMB  10.0.0.5  445  DC01  [+] acme.local\\:
SMB  10.0.0.5  445  DC01  Share           Permissions     Remark
SMB  10.0.0.5  445  DC01  -----           -----------     ------
SMB  10.0.0.5  445  DC01  ADMIN$                          Remote Admin
SMB  10.0.0.5  445  DC01  IPC$            READ            Remote IPC
SMB  10.0.0.5  445  DC01  NETLOGON        READ            Logon server share
SMB  10.0.0.5  445  DC01  SYSVOL          READ            Logon server share
SMB  10.0.0.5  445  DC01  Data            READ,WRITE      Department files";

    const USERS: &str = "\
SMB  10.0.0.5  445  DC01  [*] Enumerated domain user(s)
SMB  10.0.0.5  445  DC01  acme.local\\Administrator   badpwdcount: 0
SMB  10.0.0.5  445  DC01  acme.local\\svc_web         badpwdcount: 1
SMB  10.0.0.5  445  DC01  acme.local\\Administrator   (dup)";

    #[test]
    fn detects_null_session_and_shares() {
        assert!(null_session_allowed(SHARES));
        let shares = parse_shares(SHARES);
        let names: Vec<&str> = shares.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["ADMIN$", "IPC$", "NETLOGON", "SYSVOL", "Data"]);

        let sysvol = shares.iter().find(|s| s.name == "SYSVOL").unwrap();
        assert!(sysvol.readable, "readable SYSVOL ⇒ GPP hunting");

        let data = shares.iter().find(|s| s.name == "Data").unwrap();
        assert!(data.readable && data.writable);

        let admin = shares.iter().find(|s| s.name == "ADMIN$").unwrap();
        assert!(!admin.readable);
    }

    #[test]
    fn parses_and_dedups_users() {
        let users = parse_users(USERS);
        assert_eq!(users, vec!["Administrator", "svc_web"]);
    }
}
