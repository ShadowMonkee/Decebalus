use chrono::{DateTime, Duration, Utc};
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};
use crate::models::{Config, Credential, CveDetail, DisplayStatus, Engagement, Fact, Finding, Host, HostEvent, HostStatus, Job, JobPriority, Log, Wordlist};
use crate::services::crypto;

// ==================== JOB REPOSITORY ====================

/// Create a new job in the database
pub async fn create_job(pool: &SqlitePool, job: &Job) -> Result<(), sqlx::Error> {
    let priority_int = match job.priority {
        JobPriority::LOW => 0,
        JobPriority::NORMAL => 1,
        JobPriority::HIGH => 2,
        JobPriority::CRITICAL => 3,
    };

    sqlx::query(
        "INSERT INTO jobs (id, job_type, status, priority, results, scheduled_at, config) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    )
    .bind(&job.id)
    .bind(&job.job_type)
    .bind(&job.status)
    .bind(priority_int)
    .bind(&job.results)
    .bind(&job.scheduled_at)
    .bind(&job.config)
    .execute(pool)
    .await?;
    
    Ok(())
}

/// Get a job by ID
pub async fn get_job(pool: &SqlitePool, id: &str) -> Result<Option<Job>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, job_type, status, priority, results, created_at, scheduled_at, config FROM jobs WHERE id = ?1"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| self::from_row(&r)))
}

/// List all jobs
pub async fn list_jobs(pool: &SqlitePool) -> Result<Vec<Job>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, job_type, status, priority, results, created_at, scheduled_at, config FROM jobs ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await?;
    
    let jobs = rows.into_iter().map(|r| {
        let priority_int = r.get::<i32, _>("priority");
        let priority = match priority_int {
            0 => JobPriority::LOW,
            1 => JobPriority::NORMAL,
            2 => JobPriority::HIGH,
            3 => JobPriority::CRITICAL,
            _ => JobPriority::NORMAL,
        };
        
        Job {
        id: r.get("id"),
        job_type: r.get("job_type"),
        status: r.get("status"),
        priority: priority,
        results: r.get("results"),
        created_at: r.get("created_at"),
        scheduled_at: r.get("scheduled_at"),
        config: r.get("config"),
        }
    }).collect();
    
    Ok(jobs)
}

/// Update job status
pub async fn update_job_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE jobs SET status = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2"
    )
    .bind(status)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Atomically transition a job from `queued`/`scheduled` to `running`.
///
/// Returns `true` only if THIS call performed the transition (i.e. we now own the
/// job's execution), and `false` if the job was already claimed by another worker or
/// is otherwise no longer in a startable state (e.g. cancelled between queueing and
/// pickup). This is the concurrency guard that prevents two overlapping `run_queue`
/// passes — created quickly in succession, or a create racing the scheduler tick —
/// from both running the same job. The check-and-set is a single UPDATE so SQLite
/// serialises it; there is no read-then-write window for a second worker to slip into.
pub async fn claim_job(pool: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE jobs SET status = 'running', updated_at = CURRENT_TIMESTAMP \
         WHERE id = ?1 AND status IN ('queued', 'scheduled')"
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_running_jobs(pool: &SqlitePool) -> Result<Vec<Job>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, job_type, status, priority, results, created_at, scheduled_at, config FROM jobs WHERE status = 'running'")
        .fetch_all(pool)
        .await?;
    
    Ok(rows.into_iter().map(|r| self::from_row(&r)).collect())
}

pub async fn get_queued_jobs(pool: &SqlitePool) -> Result<Vec<Job>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, job_type, status, priority, results, created_at, scheduled_at, config FROM jobs WHERE status = 'queued'")
        .fetch_all(pool)
        .await?;
    
    Ok(rows.into_iter().map(|r| self::from_row(&r)).collect())
}

pub async fn get_scheduled_jobs_due(
    pool: &SqlitePool,
    now: DateTime<Utc>,
) -> Result<Vec<Job>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, job_type, status, priority, results, created_at, scheduled_at, config FROM jobs
         WHERE status = 'scheduled' 
         AND scheduled_at < ?1"
    )
    .bind(now.timestamp())
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| self::from_row(&r)).collect())
}

/// Update job results
pub async fn update_job_results(
    pool: &SqlitePool,
    id: &str,
    results: Option<String>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE jobs SET results = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = ?2"
    )
    .bind(results)
    .bind(id)
    .execute(pool)
    .await?;
    
    Ok(())
}

pub fn from_row(row: &SqliteRow) -> Job {
    let priority_int = row.get::<i32, _>("priority");
    let priority = match priority_int {
        0 => JobPriority::LOW,
        1 => JobPriority::NORMAL,
        2 => JobPriority::HIGH,
        3 => JobPriority::CRITICAL,
        _ => JobPriority::NORMAL,
    };

    Job {
        id: row.get("id"),
        job_type: row.get("job_type"),
        status: row.get("status"),
        priority,
        results: row.get("results"),
        created_at: row.get("created_at"),
        scheduled_at: row.get("scheduled_at"),
        config: row.get("config")
    }
}


// ==================== HOST REPOSITORY ====================

/// Create or update a host
pub async fn upsert_host(pool: &SqlitePool, host: &Host) -> Result<(), sqlx::Error> {
    let ports_json = serde_json::to_string(&host.ports).unwrap_or_else(|_| "[]".to_string());
    let banners_json = serde_json::to_string(&host.banners).unwrap_or_else(|_| "[]".to_string());
    let services_json = serde_json::to_string(&host.services).unwrap_or_else(|_| "[]".to_string());
    let vulns_json = serde_json::to_string(&host.vulnerabilities).unwrap_or_else(|_| "[]".to_string());
    let status_str = serde_json::to_string(&host.status)
        .unwrap_or_else(|_| "\"Unknown\"".to_string())
        .trim_matches('"')
        .to_string();

    sqlx::query(
        r#"
        INSERT INTO hosts (ip, ports, banners, last_seen, first_seen, os, os_version, device_type, mac_address, hostname, status, services, vulnerabilities)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
        ON CONFLICT(ip) DO UPDATE SET
            ports = ?2,
            banners = ?3,
            last_seen = ?4,
            os = ?6,
            os_version = ?7,
            device_type = ?8,
            mac_address = ?9,
            hostname = ?10,
            status = ?11,
            services = ?12,
            vulnerabilities = ?13,
            updated_at = CURRENT_TIMESTAMP
        "#
    )
    .bind(&host.ip)
    .bind(ports_json)
    .bind(banners_json)
    .bind(&host.last_seen)
    .bind(&host.first_seen)
    .bind(&host.os)
    .bind(&host.os_version)
    .bind(&host.device_type)
    .bind(&host.mac_address)
    .bind(&host.hostname)
    .bind(status_str)
    .bind(services_json)
    .bind(vulns_json)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get a host by IP
pub async fn get_host(pool: &SqlitePool, ip: &str) -> Result<Option<Host>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT ip, ports, banners, last_seen, first_seen, os, os_version, device_type, mac_address, hostname, status, services, vulnerabilities FROM hosts WHERE ip = ?1"
    )
    .bind(ip)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| host_from_row(&r)))
}

/// Find a host by MAC address — used to detect DHCP IP reassignments.
pub async fn find_host_by_mac(pool: &SqlitePool, mac: &str) -> Result<Option<Host>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT ip, ports, banners, last_seen, first_seen, os, os_version, device_type, mac_address, hostname, status, services, vulnerabilities FROM hosts WHERE mac_address = ?1 LIMIT 1"
    )
    .bind(mac)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| host_from_row(&r)))
}

/// Delete a host record by IP.
pub async fn delete_host(pool: &SqlitePool, ip: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM hosts WHERE ip = ?1")
        .bind(ip)
        .execute(pool)
        .await?;
    Ok(())
}

/// List all hosts
pub async fn list_hosts(pool: &SqlitePool) -> Result<Vec<Host>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT ip, ports, banners, last_seen, first_seen, os, os_version, device_type, mac_address, hostname, status, services, vulnerabilities FROM hosts ORDER BY \
         CAST(SUBSTR(ip, 1, INSTR(ip, '.')-1) AS INTEGER), \
         CAST(SUBSTR(ip, INSTR(ip, '.')+1, INSTR(SUBSTR(ip, INSTR(ip, '.')+1), '.')-1) AS INTEGER), \
         CAST(SUBSTR(ip, INSTR(ip, '.')+INSTR(SUBSTR(ip, INSTR(ip, '.')+1), '.')+1, INSTR(SUBSTR(ip, INSTR(ip, '.')+INSTR(SUBSTR(ip, INSTR(ip, '.')+1), '.')+1), '.')-1) AS INTEGER), \
         CAST(SUBSTR(ip, INSTR(ip, '.')+INSTR(SUBSTR(ip, INSTR(ip, '.')+1), '.')+INSTR(SUBSTR(ip, INSTR(ip, '.')+INSTR(SUBSTR(ip, INSTR(ip, '.')+1), '.')+1), '.')+1) AS INTEGER)"
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| host_from_row(&r)).collect())
}

fn host_from_row(r: &SqliteRow) -> Host {
    let ports: Vec<crate::models::Port> = r.try_get::<String, _>("ports")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let banners: Vec<String> = r.try_get::<String, _>("banners")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let services: Vec<crate::models::Service> = r.try_get::<String, _>("services")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let vulnerabilities: Vec<crate::models::Vulnerability> = r.try_get::<String, _>("vulnerabilities")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let status = match r.try_get::<String, _>("status").as_deref() {
        Ok("Up") => crate::models::HostStatus::Up,
        Ok("Down") => crate::models::HostStatus::Down,
        _ => crate::models::HostStatus::Unknown,
    };

    Host {
        ip: r.get("ip"),
        ports,
        banners,
        last_seen: r.get("last_seen"),
        first_seen: r.try_get("first_seen").unwrap_or_else(|_| r.get("last_seen")),
        os: r.try_get("os").ok().flatten(),
        os_version: r.try_get("os_version").ok().flatten(),
        device_type: r.try_get("device_type").ok().flatten(),
        mac_address: r.try_get("mac_address").ok().flatten(),
        hostname: r.try_get("hostname").ok().flatten(),
        status,
        services,
        vulnerabilities,
    }
}

// ==================== CONFIG REPOSITORY ====================

/// Get configuration
pub async fn get_config(pool: &SqlitePool) -> Result<Config, sqlx::Error> {
    let rows = sqlx::query("SELECT key, value FROM config")
        .fetch_all(pool)
        .await?;
    
    let mut settings = serde_json::Map::new();
    
    for row in rows {
        let key: String = row.get("key");
        let value: String = row.get("value");
        
        if let Ok(json_value) = serde_json::from_str(&value) {
            settings.insert(key, json_value);
        }
    }
    
    Ok(Config {
        settings: serde_json::Value::Object(settings),
    })
}

/// Update configuration
pub async fn update_config(pool: &SqlitePool, config: &Config) -> Result<(), sqlx::Error> {
    // Clear existing config
    sqlx::query("DELETE FROM config").execute(pool).await?;
    
    // Insert new config
    if let Some(obj) = config.settings.as_object() {
        for (key, value) in obj {
            let value_str = serde_json::to_string(value).unwrap();
            
            sqlx::query(
                "INSERT INTO config (key, value) VALUES (?1, ?2)"
            )
            .bind(key)
            .bind(value_str)
            .execute(pool)
            .await?;
        }
    }
    
    Ok(())
}

// ==================== DISPLAY STATUS REPOSITORY ====================

/// Get display status
pub async fn get_display_status(pool: &SqlitePool) -> Result<DisplayStatus, sqlx::Error> {
    let row = sqlx::query(
        "SELECT status, last_update FROM display_status WHERE id = 1"
    )
    .fetch_one(pool)
    .await?;
    
    Ok(DisplayStatus {
        status: row.get("status"),
        last_update: row.get("last_update"),
    })
}

/// Update display status
pub async fn update_display_status(
    pool: &SqlitePool,
    status: &DisplayStatus,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE display_status SET status = ?1, last_update = ?2, updated_at = CURRENT_TIMESTAMP WHERE id = 1"
    )
    .bind(&status.status)
    .bind(&status.last_update)
    .execute(pool)
    .await?;
    
    Ok(())
}


// ==================== LOGS ====================

pub async fn add_log(
    pool: &SqlitePool,
    severity: &str,
    service: &str,
    module: Option<&str>,
    job_id: Option<&str>,
    content: &str,
) -> Result<(), sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO logs (id, severity, service, module, job_id, content, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP)"
    )
    .bind(id)
    .bind(severity)
    .bind(service)
    .bind(module)
    .bind(job_id)
    .bind(content)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_logs(pool: &SqlitePool) -> Result<Vec<Log>, sqlx::Error> {
    let rows = sqlx::query(
        r#"
        SELECT id, created_at, severity, service, module, job_id, content
        FROM logs
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool)
    .await?;

    let logs = rows.into_iter().map(|row| {
        Log {
            id: row.get("id"),
            created_at: row.get("created_at"),
            severity: row.get("severity"),
            service: row.get("service"),
            module: row.try_get("module").ok().flatten(),
            job_id: row.try_get("job_id").ok().flatten(),
            content: row.get("content"),
        }
    }).collect();

    Ok(logs)
}

pub async fn get_logs_by_job_id(pool: &SqlitePool, job_id: String) -> Result<Vec<Log>, sqlx::Error> {
    let rows = sqlx::query(
        r#"
        SELECT id, created_at, severity, service, module, job_id, content
        FROM logs
        WHERE job_id = ?1
        ORDER BY datetime(created_at) ASC
        "#
    )
    .bind(job_id)
    .fetch_all(pool)
    .await?;

    let logs = rows.into_iter().map(|row| {
        Log {
            id: row.get("id"),
            created_at: row.get("created_at"),
            severity: row.get("severity"),
            service: row.get("service"),
            module: row.try_get("module").ok().flatten(),
            job_id: row.try_get("job_id").ok().flatten(),
            content: row.get("content"),
        }
    }).collect();

    Ok(logs)
}

pub async fn cleanup_old_logs(pool: &SqlitePool, days: i64) -> Result<u64, sqlx::Error> {
    // Calculate the cutoff timestamp
    let cutoff_date = (Utc::now() - Duration::days(days)).to_rfc3339();

    // Delete logs older than the cutoff date
    let result = sqlx::query("DELETE FROM logs WHERE created_at < ?1")
        .bind(cutoff_date)
        .execute(pool)
        .await?;

    let deleted = result.rows_affected();
    tracing::info!("🧹 Deleted {} old logs (older than {} days)", deleted, days);

    Ok(deleted)
}

// ==================== CVE DETAIL REPOSITORY ====================

fn cve_from_row(r: &SqliteRow) -> CveDetail {
    let refs_json: String = r.try_get("references_json").unwrap_or_default();
    let references: Vec<String> = serde_json::from_str(&refs_json).unwrap_or_default();
    CveDetail {
        cve_id:           r.get("cve_id"),
        description:      r.get("description"),
        cvss_v3_score:    r.try_get("cvss_v3_score").ok().flatten(),
        cvss_v3_severity: r.try_get("cvss_v3_severity").ok().flatten(),
        cvss_v2_score:    r.try_get("cvss_v2_score").ok().flatten(),
        cvss_v2_severity: r.try_get("cvss_v2_severity").ok().flatten(),
        published_at:     r.try_get("published_at").ok().flatten(),
        references,
        fetched_at:       r.get("fetched_at"),
    }
}

/// Look up a single CVE from the local cache.
pub async fn get_cve_detail(pool: &SqlitePool, cve_id: &str) -> Result<Option<CveDetail>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT cve_id, description, cvss_v3_score, cvss_v3_severity, cvss_v2_score, \
         cvss_v2_severity, published_at, references_json, fetched_at \
         FROM cve_details WHERE cve_id = ?1"
    )
    .bind(cve_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(cve_from_row))
}

/// Insert or replace a CVE record in the local cache.
pub async fn upsert_cve_detail(pool: &SqlitePool, detail: &CveDetail) -> Result<(), sqlx::Error> {
    let refs_json = serde_json::to_string(&detail.references).unwrap_or_else(|_| "[]".to_string());
    sqlx::query(
        "INSERT INTO cve_details \
         (cve_id, description, cvss_v3_score, cvss_v3_severity, cvss_v2_score, \
          cvss_v2_severity, published_at, references_json, fetched_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) \
         ON CONFLICT(cve_id) DO UPDATE SET \
           description      = excluded.description, \
           cvss_v3_score    = excluded.cvss_v3_score, \
           cvss_v3_severity = excluded.cvss_v3_severity, \
           cvss_v2_score    = excluded.cvss_v2_score, \
           cvss_v2_severity = excluded.cvss_v2_severity, \
           published_at     = excluded.published_at, \
           references_json  = excluded.references_json, \
           fetched_at       = excluded.fetched_at"
    )
    .bind(&detail.cve_id)
    .bind(&detail.description)
    .bind(detail.cvss_v3_score)
    .bind(&detail.cvss_v3_severity)
    .bind(detail.cvss_v2_score)
    .bind(&detail.cvss_v2_severity)
    .bind(&detail.published_at)
    .bind(&refs_json)
    .bind(&detail.fetched_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// List all cached CVE records, ordered by CVSS v3 score descending.
pub async fn list_cve_details(pool: &SqlitePool) -> Result<Vec<CveDetail>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT cve_id, description, cvss_v3_score, cvss_v3_severity, cvss_v2_score, \
         cvss_v2_severity, published_at, references_json, fetched_at \
         FROM cve_details ORDER BY cvss_v3_score DESC NULLS LAST, cve_id ASC"
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(cve_from_row).collect())
}

/// Return CVE IDs that exist in host vulnerabilities but have no cached detail.
pub async fn get_unenriched_cve_ids(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    // Collect all CVE IDs stored in host vulnerability blobs
    let rows = sqlx::query("SELECT vulnerabilities FROM hosts")
        .fetch_all(pool)
        .await?;

    let mut all_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for row in &rows {
        let json: String = row.try_get("vulnerabilities").unwrap_or_default();
        if let Ok(vulns) = serde_json::from_str::<Vec<serde_json::Value>>(&json) {
            for v in vulns {
                if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
                    all_ids.insert(id.to_string());
                }
            }
        }
    }

    if all_ids.is_empty() {
        return Ok(vec![]);
    }

    // Filter out IDs already cached
    let cached: std::collections::HashSet<String> = sqlx::query("SELECT cve_id FROM cve_details")
        .fetch_all(pool)
        .await?
        .iter()
        .map(|r| r.get::<String, _>("cve_id"))
        .collect();

    Ok(all_ids.difference(&cached).cloned().collect())
}

// ==================== HOST EVENTS (change detection) ====================

fn host_event_from_row(r: &SqliteRow) -> HostEvent {
    HostEvent {
        id: r.get("id"),
        created_at: r.get("created_at"),
        host_ip: r.get("host_ip"),
        event_type: r.get("event_type"),
        detail: r.try_get("detail").ok().flatten(),
        severity: r.try_get("severity").ok().flatten(),
    }
}

/// Record a single change event for a host.
pub async fn add_host_event(
    pool: &SqlitePool,
    host_ip: &str,
    event_type: &str,
    detail: Option<&str>,
    severity: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO host_events (host_ip, event_type, detail, severity) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(host_ip)
    .bind(event_type)
    .bind(detail)
    .bind(severity)
    .execute(pool)
    .await?;
    Ok(())
}

/// Most recent change events, newest first.
pub async fn list_host_events(pool: &SqlitePool, limit: i64) -> Result<Vec<HostEvent>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, created_at, host_ip, event_type, detail, severity \
         FROM host_events ORDER BY id DESC LIMIT ?1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(host_event_from_row).collect())
}

/// Upsert a host, first recording any detected changes against its previous state.
/// This is the change-detection entry point used by the scanner and port scanner.
pub async fn upsert_host_tracked(pool: &SqlitePool, host: &Host) -> Result<(), sqlx::Error> {
    let previous = get_host(pool, &host.ip).await.ok().flatten();
    record_host_changes(pool, previous.as_ref(), host).await;
    upsert_host(pool, host).await
}

async fn record_host_changes(pool: &SqlitePool, old: Option<&Host>, new: &Host) {
    use std::collections::HashSet;

    let Some(old) = old else {
        let _ = add_host_event(pool, &new.ip, "host_new", new.hostname.as_deref(), None).await;
        return;
    };

    // Status transitions.
    if old.status != new.status {
        match new.status {
            HostStatus::Up => {
                let _ = add_host_event(pool, &new.ip, "host_up", new.hostname.as_deref(), None).await;
            }
            HostStatus::Down => {
                let _ = add_host_event(pool, &new.ip, "host_down", None, None).await;
            }
            HostStatus::Unknown => {}
        }
    }

    // Newly opened ports.
    let old_open: HashSet<u16> = old
        .ports
        .iter()
        .filter(|p| p.status == "open")
        .map(|p| p.number)
        .collect();
    for p in new.ports.iter().filter(|p| p.status == "open") {
        if !old_open.contains(&p.number) {
            let detail = match &p.service {
                Some(s) => format!("{}/{}", p.number, s),
                None => p.number.to_string(),
            };
            let _ = add_host_event(pool, &new.ip, "port_opened", Some(detail.as_str()), None).await;
        }
    }

    // Newly detected vulnerabilities.
    let old_vulns: HashSet<&str> = old.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
    for v in &new.vulnerabilities {
        if !old_vulns.contains(v.id.as_str()) {
            let _ = add_host_event(
                pool,
                &new.ip,
                "vuln_new",
                Some(v.id.as_str()),
                Some(v.severity.as_str()),
            )
            .await;
        }
    }
}

// ==================== ENGAGEMENT REPOSITORY ====================

fn engagement_from_row(r: &SqliteRow) -> Engagement {
    let scope_cidrs: Vec<String> = r
        .try_get::<String, _>("scope_cidrs")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    Engagement {
        id: r.get("id"),
        name: r.get("name"),
        scope_cidrs,
        domain: r.try_get("domain").ok().flatten(),
        dc_ip: r.try_get("dc_ip").ok().flatten(),
        status: r.get("status"),
        created_at: r.get("created_at"),
    }
}

/// Create a new engagement.
pub async fn create_engagement(pool: &SqlitePool, e: &Engagement) -> Result<(), sqlx::Error> {
    let scope_json = serde_json::to_string(&e.scope_cidrs).unwrap_or_else(|_| "[]".to_string());
    sqlx::query(
        "INSERT INTO engagements (id, name, scope_cidrs, domain, dc_ip, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&e.id)
    .bind(&e.name)
    .bind(scope_json)
    .bind(&e.domain)
    .bind(&e.dc_ip)
    .bind(&e.status)
    .execute(pool)
    .await?;
    Ok(())
}

/// Get an engagement by ID.
pub async fn get_engagement(pool: &SqlitePool, id: &str) -> Result<Option<Engagement>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, name, scope_cidrs, domain, dc_ip, status, created_at FROM engagements WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| engagement_from_row(&r)))
}

/// List all engagements, newest first.
pub async fn list_engagements(pool: &SqlitePool) -> Result<Vec<Engagement>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, name, scope_cidrs, domain, dc_ip, status, created_at FROM engagements ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(engagement_from_row).collect())
}

/// The most recently created active engagement, if any. Anchors scope-lock and
/// is the default owner for facts/credentials/findings produced by modules.
pub async fn get_active_engagement(pool: &SqlitePool) -> Result<Option<Engagement>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, name, scope_cidrs, domain, dc_ip, status, created_at FROM engagements WHERE status = 'active' ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| engagement_from_row(&r)))
}

/// Update an engagement's status (active | archived).
pub async fn set_engagement_status(pool: &SqlitePool, id: &str, status: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE engagements SET status = ?2 WHERE id = ?1")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(())
}

/// Make exactly one engagement active, archiving any others. Ensures a
/// deterministic active engagement for scope-lock and fact/finding ownership.
pub async fn set_active_engagement(pool: &SqlitePool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE engagements SET status = 'archived' WHERE status = 'active'")
        .execute(pool)
        .await?;
    sqlx::query("UPDATE engagements SET status = 'active' WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ==================== CREDENTIAL REPOSITORY ====================

fn credential_from_row(r: &SqliteRow) -> Credential {
    let valid_on: Vec<String> = r
        .try_get::<String, _>("valid_on")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let engagement_id: String = r.get("engagement_id");
    let secret_ciphertext: String = r.get("secret");
    // Falls back to the raw column value on decrypt failure so pre-encryption rows
    // (migrated with an empty secret_hash) don't panic — they just read back as-is.
    let secret = crypto::decrypt_str(&engagement_id, &secret_ciphertext).unwrap_or(secret_ciphertext);
    Credential {
        id: r.get("id"),
        engagement_id,
        domain: r.get("domain"),
        username: r.get("username"),
        secret_type: r.get("secret_type"),
        secret,
        source_job_id: r.try_get("source_job_id").ok().flatten(),
        validated: r.try_get::<i64, _>("validated").unwrap_or(0) != 0,
        valid_on,
        privilege: r.get("privilege"),
        created_at: r.get("created_at"),
    }
}

/// Insert a credential, or upgrade an existing identical one (same engagement +
/// domain + username + secret) with fresher validation/privilege info.
///
/// `secret` is sealed with AES-256-GCM before it touches the database; dedup runs
/// on `secret_hash`, a deterministic HMAC of the plaintext, since the ciphertext's
/// random nonce means the same plaintext never encrypts to the same bytes twice.
pub async fn add_credential(pool: &SqlitePool, c: &Credential) -> Result<(), sqlx::Error> {
    let valid_on_json = serde_json::to_string(&c.valid_on).unwrap_or_else(|_| "[]".to_string());
    let secret_ciphertext = crypto::encrypt_str(&c.engagement_id, &c.secret);
    let secret_hash = crypto::secret_fingerprint(&c.engagement_id, &c.secret);
    sqlx::query(
        r#"
        INSERT INTO credentials
            (id, engagement_id, domain, username, secret_type, secret, secret_hash, source_job_id, validated, valid_on, privilege)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        ON CONFLICT(engagement_id, domain, username, secret_hash) DO UPDATE SET
            validated = MAX(validated, ?9),
            valid_on = ?10,
            privilege = ?11,
            source_job_id = COALESCE(?8, source_job_id)
        "#,
    )
    .bind(&c.id)
    .bind(&c.engagement_id)
    .bind(&c.domain)
    .bind(&c.username)
    .bind(&c.secret_type)
    .bind(secret_ciphertext)
    .bind(secret_hash)
    .bind(&c.source_job_id)
    .bind(if c.validated { 1_i64 } else { 0 })
    .bind(valid_on_json)
    .bind(&c.privilege)
    .execute(pool)
    .await?;
    Ok(())
}

/// List credentials for an engagement (pass "" for the global engagement).
pub async fn list_credentials(pool: &SqlitePool, engagement_id: &str) -> Result<Vec<Credential>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, engagement_id, domain, username, secret_type, secret, source_job_id, validated, valid_on, privilege, created_at \
         FROM credentials WHERE engagement_id = ?1 ORDER BY validated DESC, created_at DESC",
    )
    .bind(engagement_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(credential_from_row).collect())
}

// ==================== FACT REPOSITORY ====================

fn fact_from_row(r: &SqliteRow) -> Fact {
    let value: serde_json::Value = r
        .try_get::<String, _>("value")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null);
    Fact {
        id: r.try_get("id").unwrap_or(0),
        engagement_id: r.get("engagement_id"),
        subject_type: r.get("subject_type"),
        subject_id: r.get("subject_id"),
        key: r.get("key"),
        value,
        source_job_id: r.try_get("source_job_id").ok().flatten(),
        created_at: r.get("created_at"),
    }
}

/// Record (or replace) a fact about a subject. Deduped on
/// (engagement_id, subject_type, subject_id, key) so the latest value wins.
pub async fn upsert_fact(pool: &SqlitePool, f: &Fact) -> Result<(), sqlx::Error> {
    let value_json = serde_json::to_string(&f.value).unwrap_or_else(|_| "null".to_string());
    sqlx::query(
        r#"
        INSERT INTO facts (engagement_id, subject_type, subject_id, key, value, source_job_id)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(engagement_id, subject_type, subject_id, key) DO UPDATE SET
            value = ?5,
            source_job_id = COALESCE(?6, source_job_id)
        "#,
    )
    .bind(&f.engagement_id)
    .bind(&f.subject_type)
    .bind(&f.subject_id)
    .bind(&f.key)
    .bind(value_json)
    .bind(&f.source_job_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// All facts for an engagement (pass "" for the global engagement).
pub async fn list_facts(pool: &SqlitePool, engagement_id: &str) -> Result<Vec<Fact>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, engagement_id, subject_type, subject_id, key, value, source_job_id, created_at \
         FROM facts WHERE engagement_id = ?1 ORDER BY id DESC",
    )
    .bind(engagement_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(fact_from_row).collect())
}

/// Facts about a specific subject within an engagement.
pub async fn get_facts_for_subject(
    pool: &SqlitePool,
    engagement_id: &str,
    subject_type: &str,
    subject_id: &str,
) -> Result<Vec<Fact>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, engagement_id, subject_type, subject_id, key, value, source_job_id, created_at \
         FROM facts WHERE engagement_id = ?1 AND subject_type = ?2 AND subject_id = ?3 ORDER BY key",
    )
    .bind(engagement_id)
    .bind(subject_type)
    .bind(subject_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(fact_from_row).collect())
}

// ==================== FINDING REPOSITORY ====================

fn finding_from_row(r: &SqliteRow) -> Finding {
    let job_config: serde_json::Value = r
        .try_get::<String, _>("job_config")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let evidence: serde_json::Value = r
        .try_get::<String, _>("evidence")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    Finding {
        id: r.get("id"),
        engagement_id: r.get("engagement_id"),
        dedup_key: r.get("dedup_key"),
        title: r.get("title"),
        category: r.get("category"),
        value_score: r.try_get("value_score").unwrap_or(0),
        severity: r.get("severity"),
        rationale: r.get("rationale"),
        suggested_command: r.try_get("suggested_command").ok().flatten(),
        auto_runnable: r.try_get::<i64, _>("auto_runnable").unwrap_or(0) != 0,
        job_type: r.try_get("job_type").ok().flatten(),
        job_config,
        status: r.get("status"),
        evidence,
        created_at: r.get("created_at"),
    }
}

/// Insert or update a finding, deduped on (engagement_id, dedup_key). Re-running
/// the rule engine refreshes an existing finding rather than duplicating it, but
/// never resurrects one the operator dismissed or that already ran.
pub async fn upsert_finding(pool: &SqlitePool, f: &Finding) -> Result<(), sqlx::Error> {
    let job_config_json = serde_json::to_string(&f.job_config).unwrap_or_else(|_| "{}".to_string());
    let evidence_json = serde_json::to_string(&f.evidence).unwrap_or_else(|_| "{}".to_string());
    sqlx::query(
        r#"
        INSERT INTO findings
            (id, engagement_id, dedup_key, title, category, value_score, severity, rationale,
             suggested_command, auto_runnable, job_type, job_config, status, evidence)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        ON CONFLICT(engagement_id, dedup_key) DO UPDATE SET
            title = ?4,
            category = ?5,
            value_score = ?6,
            severity = ?7,
            rationale = ?8,
            suggested_command = ?9,
            auto_runnable = ?10,
            job_type = ?11,
            job_config = ?12,
            evidence = ?14
        WHERE findings.status NOT IN ('dismissed', 'done', 'running', 'queued')
        "#,
    )
    .bind(&f.id)
    .bind(&f.engagement_id)
    .bind(&f.dedup_key)
    .bind(&f.title)
    .bind(&f.category)
    .bind(f.value_score)
    .bind(&f.severity)
    .bind(&f.rationale)
    .bind(&f.suggested_command)
    .bind(if f.auto_runnable { 1_i64 } else { 0 })
    .bind(&f.job_type)
    .bind(job_config_json)
    .bind(&f.status)
    .bind(evidence_json)
    .execute(pool)
    .await?;
    Ok(())
}

/// Findings for an engagement, highest value first.
pub async fn list_findings(pool: &SqlitePool, engagement_id: &str) -> Result<Vec<Finding>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, engagement_id, dedup_key, title, category, value_score, severity, rationale, \
         suggested_command, auto_runnable, job_type, job_config, status, evidence, created_at \
         FROM findings WHERE engagement_id = ?1 ORDER BY value_score DESC, created_at DESC",
    )
    .bind(engagement_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(finding_from_row).collect())
}

/// Get a finding by ID.
pub async fn get_finding(pool: &SqlitePool, id: &str) -> Result<Option<Finding>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, engagement_id, dedup_key, title, category, value_score, severity, rationale, \
         suggested_command, auto_runnable, job_type, job_config, status, evidence, created_at \
         FROM findings WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| finding_from_row(&r)))
}

/// Update a finding's lifecycle status (suggested | queued | running | done | dismissed).
pub async fn update_finding_status(pool: &SqlitePool, id: &str, status: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE findings SET status = ?2 WHERE id = ?1")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(())
}

// ==================== WORDLIST REPOSITORY ====================

/// Insert a new saved wordlist record.
pub async fn insert_wordlist(pool: &SqlitePool, w: &Wordlist) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO wordlists (id, name, category, source, file_path, entry_count, size_bytes, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(&w.id)
    .bind(&w.name)
    .bind(&w.category)
    .bind(&w.source)
    .bind(&w.file_path)
    .bind(w.entry_count)
    .bind(w.size_bytes)
    .bind(&w.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// List all saved wordlists, newest first.
pub async fn list_wordlists(pool: &SqlitePool) -> Result<Vec<Wordlist>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, name, category, source, file_path, entry_count, size_bytes, created_at \
         FROM wordlists ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(wordlist_from_row).collect())
}

/// Get a single wordlist by ID.
pub async fn get_wordlist(pool: &SqlitePool, id: &str) -> Result<Option<Wordlist>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, name, category, source, file_path, entry_count, size_bytes, created_at \
         FROM wordlists WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| wordlist_from_row(&r)))
}

/// True if any wordlist rows with the given source exist (used to make bundled-seeding idempotent).
pub async fn wordlists_exist_with_source(pool: &SqlitePool, source: &str) -> Result<bool, sqlx::Error> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM wordlists WHERE source = ?1")
        .bind(source)
        .fetch_one(pool)
        .await?;
    Ok(count > 0)
}

/// Delete a wordlist record by ID. Callers should refuse to delete `source = 'bundled'`
/// rows (they're re-seeded on every boot) before calling this.
pub async fn delete_wordlist(pool: &SqlitePool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM wordlists WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

fn wordlist_from_row(r: &SqliteRow) -> Wordlist {
    Wordlist {
        id: r.get("id"),
        name: r.get("name"),
        category: r.get("category"),
        source: r.get("source"),
        file_path: r.get("file_path"),
        entry_count: r.get("entry_count"),
        size_bytes: r.get("size_bytes"),
        created_at: r.get("created_at"),
    }
}
