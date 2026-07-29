//! Read-only authenticated share hunting via NetExec (`--shares`).
//!
//! Lists shares readable with a known credential and flags high-interest ones
//! (SYSVOL/NETLOGON for GPP, plus common loot-bearing names). Reuses the share
//! parser from the null-session module.

use std::sync::Arc;

use serde_json::json;

use crate::db::repository;
use crate::models::Job;
use crate::state::AppState;

use super::ad_null_session::parse_shares;
use super::nxc_common::{
    active_engagement_id, creds_from_config, record_fact, require_nxc, run_nxc,
};

pub struct AdShareHunt;

impl AdShareHunt {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object().ok_or("Invalid job config")?;
        let target = job.target()?;
        let bin = require_nxc(state, &job.id, "ad-share-hunt").await?;
        let creds = creds_from_config(cfg);

        let mut args = vec!["smb".to_string(), target.clone()];
        args.extend(creds.auth_args());
        args.push("--shares".to_string());

        let _ = state
            .broadcaster
            .send(format!("scan_progress:{}:Share hunt on {}", job.id, target));

        let out = run_nxc(bin, &args, 300).await?;
        let shares = parse_shares(&out.stdout);
        let readable: Vec<String> = shares.iter().filter(|s| s.readable).map(|s| s.name.clone()).collect();
        let interesting: Vec<String> = readable.iter().filter(|n| is_interesting_share(n)).cloned().collect();

        let eng = active_engagement_id(state).await;
        record_fact(state, &eng, &job.id, "host", &target, "readable_shares", json!(readable)).await;
        if !interesting.is_empty() {
            record_fact(state, &eng, &job.id, "host", &target, "interesting_shares", json!(interesting)).await;
        }

        let msg = format!(
            "Share hunt on {}: {} readable, {} high-interest ({})",
            target,
            readable.len(),
            interesting.len(),
            interesting.join(", ")
        );
        let _ = repository::add_log(&state.db, "INFO", "attacks", Some("ad-share-hunt"), Some(&job.id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:{}", job.id, msg));

        Ok(json!({
            "target": target,
            "readable_shares": readable,
            "interesting_shares": interesting,
        })
        .to_string())
    }
}

/// Shares worth a closer look: domain policy shares (GPP) and common loot names.
pub fn is_interesting_share(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if upper == "SYSVOL" || upper == "NETLOGON" {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    const HINTS: &[&str] = &[
        "backup", "pass", "secret", "cred", "share", "home", "profile", "finance",
        "hr", "it", "admin", "transfer", "data", "dump", "key",
    ];
    HINTS.iter().any(|h| lower.contains(h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_policy_and_loot_shares() {
        assert!(is_interesting_share("SYSVOL"));
        assert!(is_interesting_share("NETLOGON"));
        assert!(is_interesting_share("Backups"));
        assert!(is_interesting_share("HR-Finance"));
        assert!(!is_interesting_share("IPC$"));
        assert!(!is_interesting_share("print$"));
    }
}
