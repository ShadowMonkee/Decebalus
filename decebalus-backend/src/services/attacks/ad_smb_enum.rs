//! Read-only AD SMB enumeration via NetExec (`nxc smb <scope>`).
//!
//! Records per-host facts — SMB signing state, SMBv1, OS, domain, hostname — that
//! the rule engine reads to propose next moves (e.g. signing-disabled ⇒ relay).

use std::sync::Arc;

use serde_json::json;

use crate::db::repository;
use crate::models::Job;
use crate::state::AppState;

use super::nxc_common::{
    active_engagement_id, creds_from_config, record_fact, require_nxc, run_nxc,
};

pub struct AdSmbEnum;

/// Parsed host line from `nxc smb` output.
#[derive(Debug, Clone, PartialEq)]
pub struct SmbHostInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub domain: Option<String>,
    pub os: Option<String>,
    pub signing: Option<bool>,
    pub smbv1: Option<bool>,
}

impl AdSmbEnum {
    pub async fn run(job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        let cfg = job.config.as_object().ok_or("Invalid job config")?;
        let target = job.target()?;
        let bin = require_nxc(state, &job.id, "ad-smb-enum").await?;
        let creds = creds_from_config(cfg);

        let mut args = vec!["smb".to_string(), target.clone()];
        args.extend(creds.auth_args());

        let _ = state
            .broadcaster
            .send(format!("scan_progress:{}:AD SMB enum on {}", job.id, target));

        let out = run_nxc(bin, &args, 300).await?;
        let hosts = parse_smb_enum(&out.stdout);

        let eng = active_engagement_id(state).await;
        let mut signing_disabled = 0;
        for h in &hosts {
            if let Some(sig) = h.signing {
                record_fact(state, &eng, &job.id, "host", &h.ip, "smb_signing", json!(sig)).await;
                if !sig {
                    signing_disabled += 1;
                }
            }
            if let Some(v1) = h.smbv1 {
                record_fact(state, &eng, &job.id, "host", &h.ip, "smbv1", json!(v1)).await;
            }
            if let Some(os) = &h.os {
                record_fact(state, &eng, &job.id, "host", &h.ip, "os", json!(os)).await;
            }
            if let Some(dom) = &h.domain {
                record_fact(state, &eng, &job.id, "host", &h.ip, "domain", json!(dom)).await;
                record_fact(state, &eng, &job.id, "domain", dom, "seen", json!(true)).await;
            }
            if let Some(name) = &h.hostname {
                record_fact(state, &eng, &job.id, "host", &h.ip, "hostname", json!(name)).await;
            }
        }

        let msg = format!(
            "AD SMB enum: {} host(s), {} with signing disabled",
            hosts.len(),
            signing_disabled
        );
        let _ = repository::add_log(&state.db, "INFO", "attacks", Some("ad-smb-enum"), Some(&job.id), &msg).await;
        let _ = state.broadcaster.send(format!("scan_progress:{}:{}", job.id, msg));

        Ok(json!({
            "target": target,
            "hosts_found": hosts.len(),
            "signing_disabled": signing_disabled,
            "hosts": hosts.iter().map(|h| json!({
                "ip": h.ip,
                "hostname": h.hostname,
                "domain": h.domain,
                "os": h.os,
                "signing": h.signing,
                "smbv1": h.smbv1,
            })).collect::<Vec<_>>(),
        })
        .to_string())
    }
}

/// Extract the value of a `(key:value)` token from an nxc line.
fn paren_value(line: &str, key: &str) -> Option<String> {
    let needle = format!("({}:", key);
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find(')')?;
    Some(rest[..end].trim().to_string())
}

/// The OS banner is the text between the `[*]` marker and the first `(...)` token.
fn os_from_line(line: &str) -> Option<String> {
    let after = line.split("[*]").nth(1)?.trim();
    let end = after.find(" (").unwrap_or(after.len());
    let os = after[..end].trim();
    (!os.is_empty()).then(|| os.to_string())
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Parse `nxc smb` stdout into per-host info. Lines look like:
/// `SMB  10.0.0.5  445  DC01  [*] Windows Server 2019 ... (name:DC01) (domain:acme.local) (signing:True) (SMBv1:False)`
pub fn parse_smb_enum(stdout: &str) -> Vec<SmbHostInfo> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        // Host banner lines carry the `[*]` marker; `[+]`/`[-]` are auth results.
        if !trimmed.starts_with("SMB") || !trimmed.contains("[*]") {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        // SMB <ip> <port> <name> ...
        let Some(ip) = tokens.get(1) else { continue };
        if ip.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        out.push(SmbHostInfo {
            ip: ip.to_string(),
            hostname: paren_value(trimmed, "name").or_else(|| tokens.get(3).map(|s| s.to_string())),
            domain: paren_value(trimmed, "domain"),
            os: os_from_line(trimmed),
            signing: paren_value(trimmed, "signing").as_deref().and_then(parse_bool),
            smbv1: paren_value(trimmed, "SMBv1").as_deref().and_then(parse_bool),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
SMB         10.0.0.5        445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:acme.local) (signing:True) (SMBv1:False)
SMB         10.0.0.20       445    WS01             [*] Windows 10 Build 19041 x64 (name:WS01) (domain:acme.local) (signing:False) (SMBv1:True)
SMB         10.0.0.20       445    WS01             [+] acme.local\\svc:pass (Pwn3d!)";

    #[test]
    fn parses_signing_domain_and_os() {
        let hosts = parse_smb_enum(SAMPLE);
        assert_eq!(hosts.len(), 2, "only host banner lines are parsed");

        let dc = &hosts[0];
        assert_eq!(dc.ip, "10.0.0.5");
        assert_eq!(dc.hostname.as_deref(), Some("DC01"));
        assert_eq!(dc.domain.as_deref(), Some("acme.local"));
        assert_eq!(dc.os.as_deref(), Some("Windows Server 2019 Build 17763 x64"));
        assert_eq!(dc.signing, Some(true));
        assert_eq!(dc.smbv1, Some(false));

        let ws = &hosts[1];
        assert_eq!(ws.ip, "10.0.0.20");
        assert_eq!(ws.signing, Some(false), "signing disabled → relay candidate");
        assert_eq!(ws.smbv1, Some(true));
    }

    #[test]
    fn ignores_non_host_lines() {
        assert!(parse_smb_enum("nothing here\n[*] banner").is_empty());
    }
}
