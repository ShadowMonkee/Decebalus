pub mod docs;
pub mod ssh_brute;
pub mod ftp_brute;
pub mod file_steal;
pub mod smb_brute;
pub mod rdp_brute;
pub mod nxc_common;
pub mod ad_smb_enum;
pub mod ad_null_session;
pub mod ad_password_policy;
pub mod ad_share_hunt;
pub mod ad_cred_validate;
pub mod ad_spray;
pub mod ad_kerberoast;
pub mod ad_asrep;
pub mod ad_adcs;
pub mod ad_relay_recon;
pub mod ad_bloodhound;

pub use ssh_brute::SshBruteForce;
pub use ftp_brute::FtpBruteForce;
pub use file_steal::FileSteal;
pub use smb_brute::SmbBruteForce;
pub use rdp_brute::RdpBruteForce;
pub use ad_smb_enum::AdSmbEnum;
pub use ad_null_session::AdNullSession;
pub use ad_password_policy::AdPasswordPolicy;
pub use ad_share_hunt::AdShareHunt;
pub use ad_cred_validate::AdCredValidate;
pub use ad_spray::AdSpray;
pub use ad_kerberoast::AdKerberoast;
pub use ad_asrep::AdAsrep;
pub use ad_adcs::AdAdcs;
pub use ad_relay_recon::AdRelayRecon;
pub use ad_bloodhound::AdBloodhound;

use async_trait::async_trait;
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::Value;
use sqlx::SqlitePool;
use std::sync::Arc;
use crate::db::repository;
use crate::models::Job;
use crate::state::AppState;

/// Metadata describing an attack/exploit module. Exposed via `GET /api/modules`
/// so the frontend can list modules and suggest ones relevant to a host's open ports.
///
/// The `safety`/`opsec_*`/`trigger_facts` fields drive the suggest-first policy:
/// `read_only` modules may be auto-run by the orchestrator, while `risky` ones are
/// surfaced as operator-triggered findings by the rule engine.
#[derive(Clone, Debug, Serialize, Default)]
pub struct ModuleMeta {
    /// Job-type string used to dispatch this module (e.g. "ssh-brute").
    pub job_type: String,
    /// Human-readable name.
    pub name: String,
    /// "attack" (brute force) | "exfil" | "enum" | "ad".
    pub category: String,
    pub description: String,
    /// Config keys the job requires.
    pub required_config: Vec<String>,
    /// Config keys the job optionally accepts.
    pub optional_config: Vec<String>,
    /// Default service port.
    pub default_port: Option<u16>,
    /// Open ports on a host that make this module relevant (for suggestions).
    pub trigger_ports: Vec<u16>,
    /// "read_only" (safe to auto-run) or "risky" (operator-triggered). Defaults to
    /// "risky" when unset via `Default` is empty — construct modules explicitly.
    pub safety: String,
    /// OPSEC noise level: "quiet" | "normal" | "loud".
    pub opsec_noise: String,
    /// Fact keys this module typically produces (hints for the rule engine).
    pub produces_facts: Vec<String>,
    /// Whether the module needs a stored credential to do useful work.
    pub requires_cred: bool,
    /// Precondition fact keys that make this module relevant (beyond trigger_ports),
    /// e.g. "smb_signing_disabled". Consumed by the rule engine.
    pub trigger_facts: Vec<String>,
}

/// A dispatchable attack/exploit module. Implemented by each concrete module and
/// enumerated by [`registry`], replacing the previous hardcoded dispatch match.
#[async_trait]
pub trait AttackModule: Send + Sync {
    fn meta(&self) -> ModuleMeta;
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String>;
}

/// All registered modules. Add a module here to make it dispatchable and listed.
pub fn registry() -> Vec<Box<dyn AttackModule>> {
    vec![
        Box::new(SshBruteForce),
        Box::new(FtpBruteForce),
        Box::new(SmbBruteForce),
        Box::new(RdpBruteForce),
        Box::new(FileSteal),
        Box::new(AdSmbEnum),
        Box::new(AdNullSession),
        Box::new(AdPasswordPolicy),
        Box::new(AdShareHunt),
        Box::new(AdCredValidate),
        Box::new(AdSpray),
        Box::new(AdKerberoast),
        Box::new(AdAsrep),
        Box::new(AdAdcs),
        Box::new(AdRelayRecon),
        Box::new(AdBloodhound),
    ]
}

/// Look up the module handling a given job-type string.
pub fn module_for(job_type: &str) -> Option<Box<dyn AttackModule>> {
    registry().into_iter().find(|m| m.meta().job_type == job_type)
}

/// Metadata for every registered module.
pub fn all_meta() -> Vec<ModuleMeta> {
    registry().iter().map(|m| m.meta()).collect()
}

#[async_trait]
impl AttackModule for SshBruteForce {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ssh-brute".into(),
            name: "SSH Brute Force".into(),
            category: "attack".into(),
            description: "Attempts SSH logins across username/password lists.".into(),
            required_config: vec!["target".into()],
            optional_config: vec!["port".into(), "usernames".into(), "passwords".into(), "usernames_wordlist_id".into(), "passwords_wordlist_id".into(), "concurrency".into()],
            default_port: Some(22),
            trigger_ports: vec![22],
            safety: "risky".into(),
            opsec_noise: "loud".into(),
            produces_facts: vec!["credential".into()],
            requires_cred: false,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        SshBruteForce::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for FtpBruteForce {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ftp-brute".into(),
            name: "FTP Brute Force".into(),
            category: "attack".into(),
            description: "Attempts FTP logins across username/password lists.".into(),
            required_config: vec!["target".into()],
            optional_config: vec!["port".into(), "usernames".into(), "passwords".into(), "usernames_wordlist_id".into(), "passwords_wordlist_id".into(), "concurrency".into()],
            default_port: Some(21),
            trigger_ports: vec![21],
            safety: "risky".into(),
            opsec_noise: "loud".into(),
            produces_facts: vec!["credential".into()],
            requires_cred: false,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        FtpBruteForce::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for SmbBruteForce {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "smb-brute".into(),
            name: "SMB Brute Force".into(),
            category: "attack".into(),
            description: "Attempts SMB logins via smbclient across username/password lists.".into(),
            required_config: vec!["target".into()],
            optional_config: vec!["port".into(), "domain".into(), "usernames".into(), "passwords".into(), "usernames_wordlist_id".into(), "passwords_wordlist_id".into(), "concurrency".into()],
            default_port: Some(445),
            trigger_ports: vec![445, 139],
            safety: "risky".into(),
            opsec_noise: "loud".into(),
            produces_facts: vec!["credential".into()],
            requires_cred: false,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        SmbBruteForce::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for RdpBruteForce {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "rdp-brute".into(),
            name: "RDP Brute Force".into(),
            category: "attack".into(),
            description: "Attempts RDP logins via FreeRDP NLA across username/password lists.".into(),
            required_config: vec!["target".into()],
            optional_config: vec!["port".into(), "domain".into(), "usernames".into(), "passwords".into(), "usernames_wordlist_id".into(), "passwords_wordlist_id".into(), "concurrency".into()],
            default_port: Some(3389),
            trigger_ports: vec![3389],
            safety: "risky".into(),
            opsec_noise: "loud".into(),
            produces_facts: vec!["credential".into()],
            requires_cred: false,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        RdpBruteForce::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for FileSteal {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "file-steal".into(),
            name: "File Steal (SFTP)".into(),
            category: "exfil".into(),
            description: "Downloads a remote file over SFTP using known credentials.".into(),
            required_config: vec!["target".into(), "username".into(), "password".into(), "remote_path".into()],
            optional_config: vec!["port".into()],
            default_port: Some(22),
            trigger_ports: vec![22],
            safety: "risky".into(),
            opsec_noise: "normal".into(),
            produces_facts: vec![],
            requires_cred: true,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        FileSteal::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for AdSmbEnum {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ad-smb-enum".into(),
            name: "AD SMB Enumeration".into(),
            category: "enum".into(),
            description: "Enumerates SMB signing, SMBv1, OS, and domain via NetExec (read-only).".into(),
            required_config: vec!["target".into()],
            optional_config: vec!["username".into(), "password".into(), "domain".into()],
            default_port: Some(445),
            trigger_ports: vec![445, 139],
            safety: "read_only".into(),
            opsec_noise: "normal".into(),
            produces_facts: vec!["smb_signing".into(), "smbv1".into(), "os".into(), "domain".into(), "hostname".into()],
            requires_cred: false,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        AdSmbEnum::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for AdNullSession {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ad-null-session".into(),
            name: "AD Null-Session Enumeration".into(),
            category: "enum".into(),
            description: "Anonymous SMB enumeration of users and shares via NetExec (read-only).".into(),
            required_config: vec!["target".into()],
            optional_config: vec![],
            default_port: Some(445),
            trigger_ports: vec![445, 139],
            safety: "read_only".into(),
            opsec_noise: "normal".into(),
            produces_facts: vec!["null_session".into(), "users".into(), "shares".into(), "readable_shares".into()],
            requires_cred: false,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        AdNullSession::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for AdPasswordPolicy {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ad-password-policy".into(),
            name: "AD Password Policy".into(),
            category: "enum".into(),
            description: "Reads the domain account-lockout policy via NetExec (feeds the lockout guard).".into(),
            required_config: vec!["target".into()],
            optional_config: vec!["username".into(), "password".into(), "domain".into()],
            default_port: Some(445),
            trigger_ports: vec![445],
            safety: "read_only".into(),
            opsec_noise: "quiet".into(),
            produces_facts: vec!["lockout_threshold".into(), "lockout_window_minutes".into(), "min_pw_length".into()],
            requires_cred: false,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        AdPasswordPolicy::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for AdShareHunt {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ad-share-hunt".into(),
            name: "AD Share Hunt".into(),
            category: "enum".into(),
            description: "Lists shares readable with a credential and flags high-interest ones (read-only).".into(),
            required_config: vec!["target".into()],
            optional_config: vec!["username".into(), "password".into(), "domain".into()],
            default_port: Some(445),
            trigger_ports: vec![445, 139],
            safety: "read_only".into(),
            opsec_noise: "normal".into(),
            produces_facts: vec!["readable_shares".into(), "interesting_shares".into()],
            requires_cred: true,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        AdShareHunt::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for AdCredValidate {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ad-cred-validate".into(),
            name: "AD Credential Validation".into(),
            category: "ad".into(),
            description: "Validates a credential over SMB and flags admin access (Pwn3d!).".into(),
            required_config: vec!["target".into(), "username".into()],
            optional_config: vec!["password".into(), "hash".into(), "domain".into()],
            default_port: Some(445),
            trigger_ports: vec![445],
            safety: "risky".into(),
            opsec_noise: "quiet".into(),
            produces_facts: vec!["valid_cred".into()],
            requires_cred: true,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        AdCredValidate::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for AdSpray {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ad-spray".into(),
            name: "AD Password Spray".into(),
            category: "ad".into(),
            description: "Lockout-aware spray of one password across many users (consults password policy).".into(),
            required_config: vec!["target".into(), "password".into()],
            optional_config: vec!["users".into(), "domain".into(), "force".into(), "lockout_buffer".into()],
            default_port: Some(445),
            trigger_ports: vec![445],
            safety: "risky".into(),
            opsec_noise: "normal".into(),
            produces_facts: vec!["credential".into()],
            requires_cred: false,
            trigger_facts: vec!["users".into()],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        AdSpray::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for AdKerberoast {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ad-kerberoast".into(),
            name: "Kerberoasting".into(),
            category: "ad".into(),
            description: "Requests TGS hashes for SPN accounts via NetExec and emits a hashcat command.".into(),
            required_config: vec!["target".into(), "username".into(), "password".into()],
            optional_config: vec!["domain".into()],
            default_port: Some(389),
            trigger_ports: vec![88, 389],
            safety: "risky".into(),
            opsec_noise: "normal".into(),
            produces_facts: vec!["roastable_spns".into()],
            requires_cred: true,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        AdKerberoast::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for AdAsrep {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ad-asrep".into(),
            name: "AS-REP Roasting".into(),
            category: "ad".into(),
            description: "Collects AS-REP hashes for accounts without Kerberos pre-auth and emits a hashcat command.".into(),
            required_config: vec!["target".into(), "username".into(), "password".into()],
            optional_config: vec!["domain".into()],
            default_port: Some(389),
            trigger_ports: vec![88, 389],
            safety: "risky".into(),
            opsec_noise: "normal".into(),
            produces_facts: vec!["asrep_roastable".into()],
            requires_cred: true,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        AdAsrep::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for AdAdcs {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ad-adcs".into(),
            name: "ADCS Misconfiguration (Certipy)".into(),
            category: "ad".into(),
            description: "Finds vulnerable certificate templates (ESC1–ESC8) via Certipy.".into(),
            required_config: vec!["target".into(), "username".into(), "password".into(), "domain".into()],
            optional_config: vec![],
            default_port: Some(389),
            trigger_ports: vec![389, 636],
            safety: "risky".into(),
            opsec_noise: "normal".into(),
            produces_facts: vec!["adcs_present".into(), "adcs_vulns".into()],
            requires_cred: true,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        AdAdcs::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for AdRelayRecon {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ad-relay-recon".into(),
            name: "NTLM Relay Recon".into(),
            category: "ad".into(),
            description: "Detection only: lists signing-disabled hosts and the relay commands to run.".into(),
            required_config: vec![],
            optional_config: vec![],
            default_port: Some(445),
            trigger_ports: vec![445],
            safety: "read_only".into(),
            opsec_noise: "quiet".into(),
            produces_facts: vec![],
            requires_cred: false,
            trigger_facts: vec!["smb_signing".into()],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        AdRelayRecon::run(job, state).await
    }
}

#[async_trait]
impl AttackModule for AdBloodhound {
    fn meta(&self) -> ModuleMeta {
        ModuleMeta {
            job_type: "ad-bloodhound".into(),
            name: "BloodHound Collection".into(),
            category: "ad".into(),
            description: "Collects AD graph data via NetExec for attack-path analysis in BloodHound.".into(),
            required_config: vec!["target".into(), "username".into(), "password".into(), "domain".into()],
            optional_config: vec!["dns_server".into()],
            default_port: Some(389),
            trigger_ports: vec![389, 636],
            safety: "risky".into(),
            opsec_noise: "loud".into(),
            produces_facts: vec!["bloodhound_collected".into()],
            requires_cred: true,
            trigger_facts: vec![],
        }
    }
    async fn execute(&self, job: &Job, state: &Arc<AppState>) -> Result<String, String> {
        AdBloodhound::run(job, state).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_concurrency_bounds_to_a_safe_range() {
        assert_eq!(clamp_concurrency(0), 1);
        assert_eq!(clamp_concurrency(20), 20);
        assert_eq!(clamp_concurrency(100), 100);
        assert_eq!(clamp_concurrency(5000), MAX_CONCURRENCY);
    }

    #[tokio::test]
    async fn credential_pairs_streams_full_cross_product_lazily() {
        let usernames = Arc::new(vec!["a".to_string(), "b".to_string()]);
        let passwords = Arc::new(vec!["1".to_string(), "2".to_string(), "3".to_string()]);

        let pairs: Vec<(String, String)> = credential_pairs(usernames, passwords).collect().await;

        assert_eq!(
            pairs,
            vec![
                ("a".to_string(), "1".to_string()),
                ("a".to_string(), "2".to_string()),
                ("a".to_string(), "3".to_string()),
                ("b".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string()),
                ("b".to_string(), "3".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn credential_pairs_handles_empty_lists_without_panicking() {
        let usernames = Arc::new(Vec::<String>::new());
        let passwords = Arc::new(vec!["1".to_string()]);
        let pairs: Vec<(String, String)> = credential_pairs(usernames, passwords).collect().await;
        assert!(pairs.is_empty());
    }

    #[tokio::test]
    async fn load_wordlist_prefers_inline_then_defaults() {
        let pool = crate::db::init_pool("sqlite::memory:").await.unwrap();

        let mut cfg = serde_json::Map::new();
        cfg.insert("passwords".into(), serde_json::json!(["a", "b"]));
        let inline = load_wordlist(&pool, &cfg, "passwords_wordlist_id", "passwords", "wordlist_path", DEFAULT_PASSWORDS).await;
        assert_eq!(inline, vec!["a".to_string(), "b".to_string()]);

        let empty = serde_json::Map::new();
        let defaults = load_wordlist(&pool, &empty, "passwords_wordlist_id", "passwords", "wordlist_path", DEFAULT_PASSWORDS).await;
        assert_eq!(defaults.len(), DEFAULT_PASSWORDS.len());
    }

    #[tokio::test]
    async fn load_wordlist_prefers_saved_wordlist_over_inline() {
        let pool = crate::db::init_pool("sqlite::memory:").await.unwrap();

        let dir = std::env::temp_dir().join(format!("decebalus_test_wl_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let file_path = dir.join("saved.txt");
        tokio::fs::write(&file_path, "saved-a\nsaved-b\n").await.unwrap();

        let wl = crate::models::Wordlist::new(
            "test list".into(),
            "password".into(),
            "custom".into(),
            file_path.to_string_lossy().to_string(),
            2,
            0,
        );
        repository::insert_wordlist(&pool, &wl).await.unwrap();

        let mut cfg = serde_json::Map::new();
        cfg.insert("passwords_wordlist_id".into(), serde_json::json!(wl.id));
        cfg.insert("passwords".into(), serde_json::json!(["a", "b"]));

        let resolved = load_wordlist(&pool, &cfg, "passwords_wordlist_id", "passwords", "wordlist_path", DEFAULT_PASSWORDS).await;
        assert_eq!(resolved, vec!["saved-a".to_string(), "saved-b".to_string()]);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn registry_covers_all_expected_modules() {
        let job_types: Vec<String> = all_meta().into_iter().map(|m| m.job_type).collect();
        for expected in ["ssh-brute", "ftp-brute", "smb-brute", "rdp-brute", "file-steal"] {
            assert!(job_types.contains(&expected.to_string()), "missing module {expected}");
        }
        // module_for resolves a known type and rejects an unknown one.
        assert!(module_for("ssh-brute").is_some());
        assert!(module_for("nope").is_none());
    }
}

/// Hard ceiling on brute-force concurrency, enforced server-side regardless of what a
/// job's config requests. Each concurrent attempt holds a socket (and, for smb/rdp,
/// a whole subprocess) open — an unbounded value can exhaust the process's file
/// descriptors and take down the entire server (including the API listener), not
/// just slow the job down. Clamp rather than trust the UI's own input cap, since
/// jobs can also be created directly via the API.
pub const MAX_CONCURRENCY: usize = 100;

/// Clamp a requested concurrency value to a sane, FD-safe range.
pub fn clamp_concurrency(requested: usize) -> usize {
    requested.clamp(1, MAX_CONCURRENCY)
}

/// Lazily stream every (username, password) pair without ever materializing the
/// full cross product. Wordlists can now be tens or hundreds of thousands of
/// entries each (downloaded SecLists tiers, not just the old built-in defaults),
/// so a naive nested loop that pushes every combo into a `FuturesUnordered` up
/// front can allocate tens of millions of pending futures before the concurrency
/// limit ever gets a chance to throttle anything — enough to OOM-kill the whole
/// process. `buffer_unordered` on the returned stream keeps only `concurrency`
/// items in flight at a time; combos are generated on demand as each slot frees up.
pub fn credential_pairs(
    usernames: Arc<Vec<String>>,
    passwords: Arc<Vec<String>>,
) -> impl futures_util::stream::Stream<Item = (String, String)> {
    let pw_len = passwords.len().max(1);
    let total = usernames.len() * passwords.len();
    futures_util::stream::iter(0..total).map(move |i| {
        let username = usernames[i / pw_len].clone();
        let password = passwords[i % pw_len].clone();
        (username, password)
    })
}

// Pi-specific credential defaults — covers common factory/default credentials.
pub const DEFAULT_USERNAMES: &[&str] = &[
    "root", "pi", "admin", "ubuntu", "user", "raspberry", "test", "guest",
];
pub const DEFAULT_PASSWORDS: &[&str] = &[
    "raspberry", "pi", "admin", "password", "1234", "12345", "root",
    "toor", "pass", "test", "admin123", "default", "letmein", "",
];

/// Load a credential list from the job config. Resolution order:
/// 1. A saved wordlist referenced by `id_key` (bundled/downloaded/custom, selected in the UI)
/// 2. Inline array at `inline_key`
/// 3. File path at `path_key` (one entry per line, # comments stripped)
/// 4. Built-in defaults
pub async fn load_wordlist(
    pool: &SqlitePool,
    config: &serde_json::Map<String, Value>,
    id_key: &str,
    inline_key: &str,
    path_key: &str,
    defaults: &[&str],
) -> Vec<String> {
    if let Some(id) = config.get(id_key).and_then(|v| v.as_str()) {
        if let Ok(Some(wl)) = repository::get_wordlist(pool, id).await {
            if let Ok(content) = tokio::fs::read_to_string(&wl.file_path).await {
                let lines: Vec<String> = content
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(String::from)
                    .collect();
                if !lines.is_empty() {
                    return lines;
                }
            }
        }
    }

    if let Some(arr) = config.get(inline_key).and_then(|v| v.as_array()) {
        let items: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        if !items.is_empty() {
            return items;
        }
    }

    if let Some(path) = config.get(path_key).and_then(|v| v.as_str()) {
        if let Ok(content) = tokio::fs::read_to_string(path).await {
            let lines: Vec<String> = content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from)
                .collect();
            if !lines.is_empty() {
                return lines;
            }
        }
    }

    defaults.iter().map(|s| s.to_string()).collect()
}
