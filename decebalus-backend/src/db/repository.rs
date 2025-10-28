use sqlx::{Row, SqlitePool, sqlite::SqliteRow};
use crate::models::{Config, DisplayStatus, Host, Job, JobPriority};

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
        "INSERT INTO jobs (id, job_type, status, priority, results) VALUES (?1, ?2, ?3, ?4, ?5)"
    )
    .bind(&job.id)
    .bind(&job.job_type)
    .bind(&job.status)
    .bind(priority_int)
    .bind(&job.results)
    .execute(pool)
    .await?;
    
    Ok(())
}

/// Get a job by ID
pub async fn get_job(pool: &SqlitePool, id: &str) -> Result<Option<Job>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, job_type, status, priority, results, created_at FROM jobs WHERE id = ?1"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| self::from_row(&r)))
}

/// List all jobs
pub async fn list_jobs(pool: &SqlitePool) -> Result<Vec<Job>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, job_type, status, priority, results, created_at FROM jobs ORDER BY created_at DESC"
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
        created_at: r.get("created_at")
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

pub async fn get_running_jobs(pool: &SqlitePool) -> Result<Vec<Job>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, job_type, status, priority, results, created_at FROM jobs WHERE status = 'running'")
        .fetch_all(pool)
        .await?;
    
    Ok(rows.into_iter().map(|r| self::from_row(&r)).collect())
}

pub async fn get_queued_jobs(pool: &SqlitePool) -> Result<Vec<Job>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, job_type, status, priority, results, created_at FROM jobs WHERE status = 'queued'")
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
    }
}


// ==================== HOST REPOSITORY ====================

/// Create or update a host
pub async fn upsert_host(pool: &SqlitePool, host: &Host) -> Result<(), sqlx::Error> {
    let ports_json = serde_json::to_string(&host.ports).unwrap();
    let banners_json = serde_json::to_string(&host.banners).unwrap();
    
    sqlx::query(
        r#"
        INSERT INTO hosts (ip, ports, banners, last_seen)
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(ip) DO UPDATE SET
            ports = ?2,
            banners = ?3,
            last_seen = ?4,
            updated_at = CURRENT_TIMESTAMP
        "#
    )
    .bind(&host.ip)
    .bind(ports_json)
    .bind(banners_json)
    .bind(&host.last_seen)
    .execute(pool)
    .await?;
    
    Ok(())
}

/// Get a host by IP
pub async fn get_host(pool: &SqlitePool, ip: &str) -> Result<Option<Host>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT ip, ports, banners, last_seen FROM hosts WHERE ip = ?1"
    )
    .bind(ip)
    .fetch_optional(pool)
    .await?;
    
    Ok(row.map(|r| {
        let ports_str: String = r.get("ports");
        let banners_str: String = r.get("banners");
        
        Host {
            ip: r.get("ip"),
            ports: serde_json::from_str(&ports_str).unwrap_or_default(),
            banners: serde_json::from_str(&banners_str).unwrap_or_default(),
            last_seen: r.get("last_seen"),
            os: todo!(),
            os_version: todo!(),
            device_type: todo!(),
            mac_address: todo!(),
            hostname: todo!(),
            status: todo!(),
            first_seen: todo!(),
            services: todo!(),
            vulnerabilities: todo!(),
        }
    }))
}

/// List all hosts
pub async fn list_hosts(pool: &SqlitePool) -> Result<Vec<Host>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT ip, ports, banners, last_seen FROM hosts ORDER BY last_seen DESC"
    )
    .fetch_all(pool)
    .await?;
    
    let hosts = rows.into_iter().map(|r| {
        let ports_str: String = r.get("ports");
        let banners_str: String = r.get("banners");
        
        Host {
            ip: r.get("ip"),
            ports: serde_json::from_str(&ports_str).unwrap_or_default(),
            banners: serde_json::from_str(&banners_str).unwrap_or_default(),
            last_seen: r.get("last_seen"),
            os: todo!(),
            os_version: todo!(),
            device_type: todo!(),
            mac_address: todo!(),
            hostname: todo!(),
            status: todo!(),
            first_seen: todo!(),
            services: todo!(),
            vulnerabilities: todo!(),
        }
    }).collect();
    
    Ok(hosts)
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