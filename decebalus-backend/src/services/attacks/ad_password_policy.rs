//! Read-only domain password-policy discovery via NetExec (`--pass-pol`).
//!
//! Records the account-lockout threshold/window and minimum password length as
//! domain facts. These feed the OPSEC lockout guard and the spray module so
//! spraying can stay safely under the lockout threshold.

use std::sync::Arc;

use serde_json::json;

use crate::db::repository;
use crate::models::Job;
use crate::state::AppState;

use super::nxc_common::{
    active_engagement_id, creds_from_config, record_fact, require_nxc, run_nxc,
};

pub struct AdPasswordPolicy;

/// Parsed lockout/complexity policy. `lockout_threshold == 0` means no lockout.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PasswordPolicy {
    pub min_length: Option<u32>,
    pub lockout_threshold: Option<u32>,
    pub lockout_window_minutes: Option<u32>,
    pub lockout_duration_minutes: Option<u32>,
}

impl AdPasswordPolicy {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object().ok_or("Invalid job config")?;
        let target = job.target()?;
        let bin = require_nxc(state, &job.id, "ad-password-policy").await?;
        let creds = creds_from_config(cfg);

        let mut args = vec!["smb".to_string(), target.clone()];
        args.extend(creds.auth_args());
        args.push("--pass-pol".to_string());

        let _ = state
            .broadcaster
            .send(format!("scan_progress:{}:Password policy on {}", job.id, target));

        let out = run_nxc(bin, &args, 180).await?;
        let pol = parse_pass_pol(&out.stdout);

        // Facts are keyed on the domain when known, else the target host.
        let eng = active_engagement_id(state).await;
        let subject_type = if creds.domain.is_empty() { "host" } else { "domain" };
        let subject_id = if creds.domain.is_empty() { target.clone() } else { creds.domain.clone() };

        if let Some(v) = pol.min_length {
            record_fact(state, &eng, &job.id, subject_type, &subject_id, "min_pw_length", json!(v)).await;
        }
        if let Some(v) = pol.lockout_threshold {
            record_fact(state, &eng, &job.id, subject_type, &subject_id, "lockout_threshold", json!(v)).await;
        }
        if let Some(v) = pol.lockout_window_minutes {
            record_fact(state, &eng, &job.id, subject_type, &subject_id, "lockout_window_minutes", json!(v)).await;
        }
        if let Some(v) = pol.lockout_duration_minutes {
            record_fact(state, &eng, &job.id, subject_type, &subject_id, "lockout_duration_minutes", json!(v)).await;
        }

        let msg = match pol.lockout_threshold {
            Some(0) | None => format!("Password policy on {}: no account lockout", subject_id),
            Some(t) => format!(
                "Password policy on {}: lockout after {} attempts / {} min window",
                subject_id,
                t,
                pol.lockout_window_minutes.unwrap_or(0)
            ),
        };
        let _ = repository::add_log(&state.db, "INFO", "attacks", Some("ad-password-policy"), Some(&job.id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:{}", job.id, msg));

        Ok(json!({
            "target": target,
            "min_pw_length": pol.min_length,
            "lockout_threshold": pol.lockout_threshold,
            "lockout_window_minutes": pol.lockout_window_minutes,
            "lockout_duration_minutes": pol.lockout_duration_minutes,
        })
        .to_string())
    }
}

/// First integer appearing after a `:` on the line.
fn int_after_colon(line: &str) -> Option<u32> {
    let after = line.rsplit(':').next()?;
    for tok in after.split_whitespace() {
        if let Ok(n) = tok.parse::<u32>() {
            return Some(n);
        }
    }
    None
}

/// Parse `nxc --pass-pol` output into a [`PasswordPolicy`]. Tolerant of the
/// "None"/"Not Set" values NetExec prints when a policy is disabled.
pub fn parse_pass_pol(stdout: &str) -> PasswordPolicy {
    let mut pol = PasswordPolicy::default();
    for line in stdout.lines() {
        let l = line.trim();
        let lower = l.to_ascii_lowercase();
        if lower.contains("minimum password length") {
            pol.min_length = int_after_colon(l);
        } else if lower.contains("account lockout threshold") {
            // "None" ⇒ no lockout ⇒ threshold 0.
            pol.lockout_threshold = Some(int_after_colon(l).unwrap_or(0));
        } else if lower.contains("reset account lockout counter") {
            pol.lockout_window_minutes = int_after_colon(l);
        } else if lower.contains("locked account duration") {
            pol.lockout_duration_minutes = int_after_colon(l);
        }
    }
    pol
}

#[cfg(test)]
mod tests {
    use super::*;

    const POL: &str = "\
SMB  10.0.0.5  445  DC01  [+] Dumping password info for domain: ACME
SMB  10.0.0.5  445  DC01  Minimum password length: 7
SMB  10.0.0.5  445  DC01  Account Lockout Threshold: 5
SMB  10.0.0.5  445  DC01  Reset Account Lockout Counter: 30 minutes
SMB  10.0.0.5  445  DC01  Locked Account Duration: 30 minutes";

    const NO_LOCKOUT: &str = "\
SMB  10.0.0.5  445  DC01  Minimum password length: 8
SMB  10.0.0.5  445  DC01  Account Lockout Threshold: None";

    #[test]
    fn parses_lockout_policy() {
        let p = parse_pass_pol(POL);
        assert_eq!(p.min_length, Some(7));
        assert_eq!(p.lockout_threshold, Some(5));
        assert_eq!(p.lockout_window_minutes, Some(30));
        assert_eq!(p.lockout_duration_minutes, Some(30));
    }

    #[test]
    fn none_threshold_means_no_lockout() {
        let p = parse_pass_pol(NO_LOCKOUT);
        assert_eq!(p.min_length, Some(8));
        assert_eq!(p.lockout_threshold, Some(0), "None ⇒ safe to spray freely");
    }
}
