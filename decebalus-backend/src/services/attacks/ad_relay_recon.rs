//! NTLM relay opportunity detection (detection only — never relays).
//!
//! Reads `smb_signing` facts gathered by `ad-smb-enum` and, for every host with
//! signing disabled, produces a relay-target list plus the exact Responder +
//! ntlmrelayx commands for the operator to run manually.

use std::sync::Arc;

use serde_json::json;

use crate::db::repository;
use crate::models::{Fact, Finding, Job};
use crate::state::AppState;

use super::nxc_common::{active_engagement_id, record_finding, save_loot};

pub struct AdRelayRecon;

impl AdRelayRecon {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let eng = active_engagement_id(state).await;
        let facts = repository::list_facts(&state.db, &eng).await.unwrap_or_default();
        let targets = relay_targets_from_facts(&facts);

        if targets.is_empty() {
            let msg = "No relay targets: SMB signing enabled everywhere, or run ad-smb-enum first.";
            let _ = repository::add_log(&state.db, "INFO", "attacks", Some("ad-relay-recon"), Some(&job.id), msg).await;
            return Ok(json!({ "relay_targets": [] }).to_string());
        }

        let loot = save_loot("relay", "targets.txt", targets.join("\n").as_bytes())
            .await
            .unwrap_or_default();

        let mut f = Finding::new(
            "relay-targets".to_string(),
            format!("SMB signing disabled on {} host(s) — NTLM relay possible", targets.len()),
        );
        f.engagement_id = eng.clone();
        f.category = "ad".into();
        f.severity = "high".into();
        f.value_score = 68;
        f.rationale = format!(
            "{} host(s) accept unsigned SMB. Coerce/poison authentication and relay it to these targets for code execution or credential capture.",
            targets.len()
        );
        f.suggested_command = Some(format!(
            "sudo responder -I <iface>   # poison, then in another shell:\nntlmrelayx.py -tf {} -smb2support -i",
            loot
        ));
        f.status = "suggested".into();
        f.evidence = json!({ "targets": targets, "loot": loot });
        record_finding(state, &f).await;

        let msg = format!("Relay recon: {} target(s) with signing disabled", targets.len());
        let _ = repository::add_log(&state.db, "INFO", "attacks", Some("ad-relay-recon"), Some(&job.id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:{}", job.id, msg));

        Ok(json!({ "relay_targets": targets, "loot": loot }).to_string())
    }
}

/// Hosts whose `smb_signing` fact is `false` — the relay candidates.
pub fn relay_targets_from_facts(facts: &[Fact]) -> Vec<String> {
    let mut out = Vec::new();
    for f in facts {
        if f.subject_type == "host" && f.key == "smb_signing" && f.value == json!(false) {
            if !out.contains(&f.subject_id) {
                out.push(f.subject_id.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(subject: &str, key: &str, value: serde_json::Value) -> Fact {
        let mut f = Fact::new("host", subject, key, value);
        f.id = 1;
        f
    }

    #[test]
    fn selects_only_signing_disabled_hosts() {
        let facts = vec![
            fact("10.0.0.5", "smb_signing", json!(true)),
            fact("10.0.0.20", "smb_signing", json!(false)),
            fact("10.0.0.21", "smb_signing", json!(false)),
            fact("10.0.0.20", "os", json!("Windows 10")),
        ];
        assert_eq!(relay_targets_from_facts(&facts), vec!["10.0.0.20", "10.0.0.21"]);
    }
}
