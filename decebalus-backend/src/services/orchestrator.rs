use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use serde_json::json;
use tokio::time::{sleep, Duration};

use crate::db::repository;
use crate::models::{HostStatus, Job, JobPriority};
use crate::services::attacks::{self, ModuleMeta};
use crate::services::JobExecutor;
use crate::settings;
use crate::state::AppState;

/// Autonomous operation loop ("Bjorn mode").
///
/// When `autonomous_enabled` is set, cycles through discover → port-scan → nmap
/// → (optional) attack, creating normal jobs and waiting for each so everything
/// shows up in the Dashboard/Logs. Recon-only unless `autonomous_attacks_enabled`.
pub struct Orchestrator;

impl Orchestrator {
    pub async fn run(state: Arc<AppState>) {
        tracing::info!("[autonomous] orchestrator started");

        // In-memory dedup so known hosts aren't re-processed every cycle within a run.
        let mut scanned: HashSet<String> = HashSet::new();
        let mut nmapped: HashSet<String> = HashSet::new();
        let mut attacked: HashSet<String> = HashSet::new();
        let mut idle_announced = false;

        loop {
            if !settings::current().autonomous_enabled {
                if !idle_announced {
                    Self::set_status(&state, "idle").await;
                    idle_announced = true;
                }
                sleep(Duration::from_secs(15)).await;
                continue;
            }
            idle_announced = false;

            Self::run_cycle(&state, &mut scanned, &mut nmapped, &mut attacked).await;

            let interval = settings::current().autonomous_interval_secs.max(30);
            Self::set_status(&state, "idle — waiting for next cycle").await;
            sleep(Duration::from_secs(interval)).await;
        }
    }

    /// One full autonomous cycle. Re-checks the enable flag between phases so
    /// toggling off stops promptly.
    async fn run_cycle(
        state: &Arc<AppState>,
        scanned: &mut HashSet<String>,
        nmapped: &mut HashSet<String>,
        attacked: &mut HashSet<String>,
    ) {
        // Phase 1 — discover the local network.
        Self::set_status(state, "discovering local network").await;
        let _ = Self::run_and_wait(state, "discovery", json!({ "target": "self" })).await;
        if !settings::current().autonomous_enabled {
            return;
        }

        // Phase 2 — port-scan Up hosts we haven't scanned yet this run.
        for ip in Self::up_host_ips(state).await {
            if scanned.contains(&ip) {
                continue;
            }
            if !settings::current().autonomous_enabled {
                return;
            }
            Self::set_status(state, &format!("port-scanning {}", ip)).await;
            let _ = Self::run_and_wait(state, "port-scan", json!({ "target": ip.as_str() })).await;
            scanned.insert(ip);
        }

        // Phase 3 — nmap Up hosts with open ports we haven't fingerprinted yet.
        // (nmap-scan auto-triggers CVE enrichment.)
        let hosts = repository::list_hosts(&state.db).await.unwrap_or_default();
        for host in &hosts {
            if host.status != HostStatus::Up || nmapped.contains(&host.ip) {
                continue;
            }
            if !host.ports.iter().any(|p| p.status == "open") {
                continue;
            }
            if !settings::current().autonomous_enabled {
                return;
            }
            Self::set_status(state, &format!("nmap {}", host.ip)).await;
            let _ = Self::run_and_wait(state, "nmap-scan", json!({ "target": host.ip.as_str() })).await;
            nmapped.insert(host.ip.clone());
        }

        // Phase 4 — attacks, strictly opt-in.
        if settings::current().autonomous_attacks_enabled {
            let metas = attacks::all_meta();
            let hosts = repository::list_hosts(&state.db).await.unwrap_or_default();
            for host in &hosts {
                if host.status != HostStatus::Up || attacked.contains(&host.ip) {
                    continue;
                }
                let open: HashSet<u16> = host
                    .ports
                    .iter()
                    .filter(|p| p.status == "open")
                    .map(|p| p.number)
                    .collect();
                let job_types = attack_job_types_for(&open, &metas);
                if job_types.is_empty() {
                    continue;
                }
                for jt in job_types {
                    if !settings::current().autonomous_attacks_enabled {
                        break;
                    }
                    Self::set_status(state, &format!("{} on {}", jt, host.ip)).await;
                    let _ = Self::run_and_wait(state, &jt, json!({ "target": host.ip.as_str() })).await;
                }
                attacked.insert(host.ip.clone());
            }
        }

        // Phase 5 — run the next-move rule engine: upsert ranked findings and
        // (suggest-first) auto-run any read-only next moves it proposes.
        Self::set_status(state, "evaluating next moves").await;
        let n = Self::run_rule_engine(state).await;
        Self::set_status(state, &format!("cycle complete — {} finding(s)", n)).await;
    }

    /// One rule-engine pass. Evaluates the rules against the current engagement
    /// snapshot, upserts the ranked findings, and — under the suggest-first policy
    /// — auto-enqueues read-only next-moves. Risky moves stay as operator-triggered
    /// suggestions. Returns the number of findings produced.
    pub async fn run_rule_engine(state: &Arc<AppState>) -> usize {
        let snap = crate::services::rules::Snapshot::load(state).await;
        let findings = crate::services::rules::evaluate(&snap);

        for f in &findings {
            let _ = repository::upsert_finding(&state.db, f).await;
            let _ = state.broadcaster.send(format!("finding_new:{}", f.title));
            crate::services::events::emit(state, "finding", serde_json::to_value(f).unwrap_or_default());
        }
        crate::services::events::emit(state, "engine", json!({ "findings": findings.len() }));

        // Suggest-first auto-run: only read-only, auto_runnable moves, and only
        // when autonomous operation is enabled.
        if settings::current().autonomous_enabled {
            let mut enqueued = false;
            for f in findings.iter().filter(|f| f.auto_runnable) {
                let Some(jt) = &f.job_type else { continue };
                let is_read_only = attacks::module_for(jt)
                    .map(|m| m.meta().safety == "read_only")
                    .unwrap_or(false);
                if !is_read_only {
                    continue;
                }
                let mut job = Job::new(jt.clone());
                job.priority = JobPriority::LOW;
                job.config = f.job_config.clone();
                if repository::create_job(&state.db, &job).await.is_ok() {
                    let _ = repository::update_finding_status(&state.db, &f.id, "queued").await;
                    enqueued = true;
                }
            }
            if enqueued {
                JobExecutor::run_queue(state).await;
            }
        }

        findings.len()
    }

    async fn up_host_ips(state: &Arc<AppState>) -> Vec<String> {
        repository::list_hosts(&state.db)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|h| h.status == HostStatus::Up)
            .map(|h| h.ip)
            .collect()
    }

    /// Create a job, nudge the queue, and wait for it to reach a terminal state.
    async fn run_and_wait(
        state: &Arc<AppState>,
        job_type: &str,
        config: serde_json::Value,
    ) -> Result<Job, String> {
        let mut job = Job::new(job_type.to_string());
        job.priority = JobPriority::LOW; // let user-initiated jobs preempt
        job.config = config;

        repository::create_job(&state.db, &job)
            .await
            .map_err(|e| e.to_string())?;

        // Start it promptly (the 30s scheduler tick would also pick it up).
        JobExecutor::run_queue(state).await;

        let deadline = Instant::now() + Duration::from_secs(1800); // 30-min safety cap
        loop {
            sleep(Duration::from_secs(2)).await;
            match repository::get_job(&state.db, &job.id).await {
                Ok(Some(j)) if j.is_completed() || j.status == "failed" || j.is_cancelled() => {
                    return Ok(j);
                }
                Ok(_) => {}
                Err(e) => return Err(e.to_string()),
            }
            if Instant::now() > deadline {
                return Err(format!("autonomous job {} ({}) timed out", job.id, job_type));
            }
        }
    }

    /// Broadcast the current autonomous phase and mirror it to the display status.
    async fn set_status(state: &Arc<AppState>, phase: &str) {
        tracing::info!("[autonomous] {}", phase);
        let _ = state.broadcaster.send(format!("autonomous:{}", phase));
        if let Ok(mut ds) = repository::get_display_status(&state.db).await {
            ds.update(format!("Autonomous: {}", phase));
            let _ = repository::update_display_status(&state.db, &ds).await;
        }
    }
}

/// Pure selection: job-types of `attack`-category modules whose trigger ports
/// intersect a host's open ports. Kept free-standing so it is unit-testable
/// without a running host or network.
pub fn attack_job_types_for(open_ports: &HashSet<u16>, metas: &[ModuleMeta]) -> Vec<String> {
    metas
        .iter()
        .filter(|m| m.category == "attack")
        .filter(|m| m.trigger_ports.iter().any(|p| open_ports.contains(p)))
        .map(|m| m.job_type.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(job_type: &str, category: &str, trigger: Vec<u16>) -> ModuleMeta {
        ModuleMeta {
            job_type: job_type.into(),
            name: job_type.into(),
            category: category.into(),
            description: String::new(),
            required_config: vec![],
            optional_config: vec![],
            default_port: None,
            trigger_ports: trigger,
            ..Default::default()
        }
    }

    #[test]
    fn selects_matching_attack_modules_by_open_port() {
        let metas = vec![
            meta("ssh-brute", "attack", vec![22]),
            meta("smb-brute", "attack", vec![445, 139]),
            meta("file-steal", "exfil", vec![22]),
        ];
        let open: HashSet<u16> = [22u16, 80].into_iter().collect();
        // Matches ssh (22); smb not open; file-steal excluded (exfil).
        assert_eq!(attack_job_types_for(&open, &metas), vec!["ssh-brute".to_string()]);
    }

    #[test]
    fn no_open_ports_yields_nothing() {
        let metas = vec![meta("ssh-brute", "attack", vec![22])];
        let empty: HashSet<u16> = HashSet::new();
        assert!(attack_job_types_for(&empty, &metas).is_empty());
    }

    #[test]
    fn excludes_exfil_even_when_port_matches() {
        let metas = vec![meta("file-steal", "exfil", vec![22])];
        let open: HashSet<u16> = [22u16].into_iter().collect();
        assert!(attack_job_types_for(&open, &metas).is_empty());
    }
}
