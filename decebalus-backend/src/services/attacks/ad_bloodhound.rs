//! BloodHound collection via NetExec LDAP (`--bloodhound --collection All`).
//! Runs the collector and raises a finding pointing at the collected archive to
//! import into BloodHound for attack-path analysis.

use std::sync::Arc;

use serde_json::json;

use crate::db::repository;
use crate::models::{Finding, Job};
use crate::state::AppState;

use super::nxc_common::{active_engagement_id, record_fact, record_finding, require_nxc, run_nxc};

pub struct AdBloodhound;

impl AdBloodhound {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object().ok_or("Invalid job config")?;
        let target = job.target()?; // DC
        let user = cfg.get("username").and_then(|v| v.as_str()).ok_or("config.username required")?;
        let pass = cfg.get("password").and_then(|v| v.as_str()).ok_or("config.password required")?;
        let domain = cfg.get("domain").and_then(|v| v.as_str()).ok_or("config.domain required")?;
        let dns = cfg.get("dns_server").and_then(|v| v.as_str()).unwrap_or(&target).to_string();
        let bin = require_nxc(state, &job.id, "ad-bloodhound").await?;

        let args = vec![
            "ldap".to_string(),
            target.clone(),
            "-u".to_string(),
            user.to_string(),
            "-p".to_string(),
            pass.to_string(),
            "-d".to_string(),
            domain.to_string(),
            "--bloodhound".to_string(),
            "--collection".to_string(),
            "All".to_string(),
            "--dns-server".to_string(),
            dns,
        ];

        let _ = state.broadcaster.send(format!("scan_progress:{}:BloodHound collection on {}", job.id, domain));
        let out = run_nxc(bin, &args, 900).await?;
        let zip = parse_bh_zip(&out.stdout);

        let eng = active_engagement_id(state).await;
        record_fact(state, &eng, &job.id, "domain", domain, "bloodhound_collected", json!(true)).await;

        let mut f = Finding::new(
            format!("bloodhound:{}", domain),
            format!("BloodHound data collected for {}", domain),
        );
        f.engagement_id = eng.clone();
        f.category = "ad".into();
        f.severity = "medium".into();
        f.value_score = 55;
        f.rationale = "Import the collected graph into BloodHound to find the shortest paths to Domain Admin.".into();
        f.suggested_command = Some(match &zip {
            Some(p) => format!("# Import into BloodHound GUI: {}", p),
            None => "# Import the generated .zip (see nxc output) into the BloodHound GUI".to_string(),
        });
        f.status = "done".into();
        f.evidence = json!({ "domain": domain, "zip": zip });
        record_finding(state, &f).await;

        let msg = format!("BloodHound collection on {} complete{}", domain, zip.as_ref().map(|z| format!(" ({})", z)).unwrap_or_default());
        let _ = repository::add_log(&state.db, "INFO", "attacks", Some("ad-bloodhound"), Some(&job.id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:{}", job.id, msg));

        Ok(json!({ "domain": domain, "zip": zip }).to_string())
    }
}

/// Extract the produced archive path from nxc's "Compressing output into <path>".
pub fn parse_bh_zip(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        if let Some(idx) = line.find("Compressing output into") {
            let rest = line[idx + "Compressing output into".len()..].trim();
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
        if let Some(tok) = line.split_whitespace().find(|t| t.ends_with(".zip")) {
            return Some(tok.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_zip_path() {
        let out = "LDAP 10.0.0.5 389 DC01 Compressing output into /tmp/20260728_bloodhound.zip";
        assert_eq!(parse_bh_zip(out).as_deref(), Some("/tmp/20260728_bloodhound.zip"));
        let out2 = "some line 20260728_acme.zip was written";
        assert_eq!(parse_bh_zip(out2).as_deref(), Some("20260728_acme.zip"));
        assert_eq!(parse_bh_zip("nothing"), None);
    }
}
