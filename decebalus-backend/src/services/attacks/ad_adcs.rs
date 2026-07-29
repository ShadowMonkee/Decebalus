//! AD Certificate Services misconfiguration check via Certipy (`certipy find`).
//! Parses vulnerable templates (ESC1–ESC8) and raises a high-value finding per
//! vulnerability with the Certipy request command to exploit it.

use std::sync::Arc;

use serde_json::json;

use crate::db::repository;
use crate::models::{Finding, Job};
use crate::state::AppState;

use super::nxc_common::{
    active_engagement_id, record_fact, record_finding, require_binary, run_tool,
};

pub struct AdAdcs;

/// A parsed ADCS vulnerability: which template and which ESC class.
#[derive(Debug, Clone, PartialEq)]
pub struct AdcsVuln {
    pub template: String,
    pub esc: String,
    pub detail: String,
}

impl AdAdcs {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object().ok_or("Invalid job config")?;
        let target = job.target()?; // DC IP
        let user = cfg.get("username").and_then(|v| v.as_str()).ok_or("config.username required")?;
        let pass = cfg.get("password").and_then(|v| v.as_str()).ok_or("config.password required")?;
        let domain = cfg.get("domain").and_then(|v| v.as_str()).ok_or("config.domain required")?;
        require_binary(state, &job.id, "ad-adcs", "certipy", "install with: pipx install certipy-ad").await?;

        let upn = format!("{}@{}", user, domain);
        let args = vec![
            "find".to_string(),
            "-u".to_string(),
            upn,
            "-p".to_string(),
            pass.to_string(),
            "-dc-ip".to_string(),
            target.clone(),
            "-vulnerable".to_string(),
            "-stdout".to_string(),
        ];

        let _ = state.broadcaster.send(format!("scan_progress:{}:ADCS check via Certipy on {}", job.id, target));
        let out = run_tool("certipy", &args, 240).await?;
        let vulns = parse_adcs(&out.stdout);

        let eng = active_engagement_id(state).await;
        record_fact(state, &eng, &job.id, "host", &target, "adcs_present", json!(true)).await;
        record_fact(state, &eng, &job.id, "host", &target, "adcs_vulns", json!(vulns.len())).await;

        for v in &vulns {
            let mut f = Finding::new(
                format!("adcs-{}:{}:{}", v.esc.to_lowercase(), target, v.template),
                format!("ADCS {} on template {}", v.esc, v.template),
            );
            f.engagement_id = eng.clone();
            f.category = "ad".into();
            f.severity = "critical".into();
            f.value_score = 90;
            f.rationale = if v.detail.is_empty() {
                format!("Template {} is vulnerable to {} — can lead to domain privilege escalation.", v.template, v.esc)
            } else {
                v.detail.clone()
            };
            f.suggested_command = Some(format!(
                "certipy req -u {}@{} -p '<pass>' -dc-ip {} -ca '<CA>' -template {} -upn administrator@{}",
                user, domain, target, v.template, domain
            ));
            f.status = "done".into();
            f.evidence = json!({ "target": target, "template": v.template, "esc": v.esc });
            record_finding(state, &f).await;
        }

        let msg = format!("ADCS on {}: {} vulnerable template(s)", target, vulns.len());
        let _ = repository::add_log(&state.db, "INFO", "attacks", Some("ad-adcs"), Some(&job.id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:{}", job.id, msg));

        Ok(json!({
            "target": target,
            "vulnerabilities": vulns.iter().map(|v| json!({
                "template": v.template, "esc": v.esc, "detail": v.detail
            })).collect::<Vec<_>>(),
        })
        .to_string())
    }
}

/// Parse `certipy find -vulnerable -stdout` text output. Tracks the current
/// template name and pairs each `ESCx : ...` line under it.
pub fn parse_adcs(stdout: &str) -> Vec<AdcsVuln> {
    let mut out = Vec::new();
    let mut current_template = String::new();
    for line in stdout.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("Template Name") {
            if let Some(idx) = rest.find(':') {
                current_template = rest[idx + 1..].trim().to_string();
            }
        } else if l.starts_with("ESC") {
            let mut parts = l.splitn(2, ':');
            let esc = parts.next().unwrap_or("").trim().to_string();
            let detail = parts.next().unwrap_or("").trim().to_string();
            // Only accept ESC ids like ESC1..ESC16 (avoid stray words).
            if esc.len() >= 4 && esc[3..].chars().all(|c| c.is_ascii_digit()) {
                out.push(AdcsVuln { template: current_template.clone(), esc, detail });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIND: &str = "\
Certificate Templates
  0
    Template Name                       : VulnTemplate
    Enabled                             : True
    [!] Vulnerabilities
      ESC1                              : 'ACME.LOCAL\\Domain Users' can enroll and supply subject
  1
    Template Name                       : WebServer
    [!] Vulnerabilities
      ESC8                              : Web enrollment is vulnerable to relay";

    #[test]
    fn parses_esc_vulnerabilities() {
        let vulns = parse_adcs(FIND);
        assert_eq!(vulns.len(), 2);
        assert_eq!(vulns[0].template, "VulnTemplate");
        assert_eq!(vulns[0].esc, "ESC1");
        assert!(vulns[0].detail.contains("can enroll"));
        assert_eq!(vulns[1].template, "WebServer");
        assert_eq!(vulns[1].esc, "ESC8");
    }
}
