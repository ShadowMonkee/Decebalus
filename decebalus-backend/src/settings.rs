//! Runtime settings singleton.
//!
//! Settings are resolved with a three-tier precedence: a value stored in the
//! `config` table (set via the Settings UI) wins; otherwise the matching env var;
//! otherwise a built-in default. The resolved snapshot lives in a process-global
//! `RwLock` so any module can read the current values via [`current`] without
//! threading a config object through every function signature. Call [`reload`]
//! after the config table changes to refresh the snapshot.

use once_cell::sync::OnceCell;
use serde_json::Value;
use sqlx::SqlitePool;
use std::sync::RwLock;

use crate::db::repository;

/// Default TCP ports probed during the fallback host-liveness check (when ARP/ICMP
/// are unavailable). Kept here so it is configurable via `fallback_ports`.
pub fn default_fallback_ports() -> Vec<u16> {
    vec![
        // Common services
        80, 443, 8080, 8443, 22, 23, 21, 25, 587, 445, 139, 3389, 3306, 5432, 6379,
        9100, // Prometheus node exporter
        1883, 8883, // MQTT
        554, 8554, // RTSP (cameras / streaming)
        7547, // TR-069 (router/ISP management)
        49152, 52869, // UPnP
        8123, // Home Assistant
        9000, 5001, // NAS / misc embedded
        102, 502, 4840, 623, // Industrial: S7, Modbus, OPC-UA, IPMI/BMC
    ]
}

/// Resolved runtime configuration snapshot.
#[derive(Clone, Debug)]
pub struct Settings {
    // Scanning
    pub max_threads: usize,
    pub max_scan_concurrency: usize,
    pub max_discover_threads: usize,
    pub port_scan_timeout_ms: u64,
    pub host_alive_timeout_ms: u64,
    pub fallback_ports: Vec<u16>,
    // CVE enrichment
    pub nvd_api_key: Option<String>,
    // Logging
    pub log_level: String,
    pub log_retention_days: i64,
    // Autonomous operation (consumed by the orchestrator)
    pub autonomous_enabled: bool,
    pub autonomous_attacks_enabled: bool,
    pub autonomous_interval_secs: u64,
    // OPSEC — keep engagements quiet and lockout-safe
    pub opsec_quiet: bool,
    pub opsec_jitter_ms: u64,
    pub spray_lockout_buffer: u64,
    // Identity
    pub device_name: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_threads: 5,
            max_scan_concurrency: 500,
            max_discover_threads: 256,
            port_scan_timeout_ms: 200,
            host_alive_timeout_ms: 500,
            fallback_ports: default_fallback_ports(),
            nvd_api_key: None,
            log_level: "info".to_string(),
            log_retention_days: 30,
            autonomous_enabled: false,
            autonomous_attacks_enabled: false,
            autonomous_interval_secs: 900,
            opsec_quiet: false,
            opsec_jitter_ms: 0,
            spray_lockout_buffer: 1,
            device_name: "decebalus-01".to_string(),
        }
    }
}

impl Settings {
    /// Load and resolve settings from the `config` table (falling back to env/defaults).
    pub async fn load(pool: &SqlitePool) -> Self {
        let stored = repository::get_config(pool)
            .await
            .map(|c| c.settings)
            .unwrap_or_else(|_| Value::Object(Default::default()));
        Self::from_stored(&stored)
    }

    /// Resolve settings from an already-loaded stored JSON object.
    pub fn from_stored(stored: &Value) -> Self {
        let d = Settings::default();
        Settings {
            max_threads: get_usize(stored, "max_threads", "MAX_THREADS", d.max_threads),
            max_scan_concurrency: get_usize(
                stored,
                "max_scan_concurrency",
                "MAX_SCAN_CONCURRENCY",
                d.max_scan_concurrency,
            ),
            max_discover_threads: get_usize(
                stored,
                "max_discover_threads",
                "MAX_DISCOVER_THREADS",
                d.max_discover_threads,
            ),
            port_scan_timeout_ms: get_u64(
                stored,
                "port_scan_timeout_ms",
                "PORT_SCAN_TIMEOUT_MS",
                d.port_scan_timeout_ms,
            ),
            host_alive_timeout_ms: get_u64(
                stored,
                "host_alive_timeout_ms",
                "HOST_ALIVE_TIMEOUT_MS",
                d.host_alive_timeout_ms,
            ),
            fallback_ports: get_ports(stored, "fallback_ports", d.fallback_ports),
            nvd_api_key: get_opt_string(stored, "nvd_api_key", "NVD_API_KEY"),
            log_level: get_string(stored, "log_level", "LOG_LEVEL", &d.log_level),
            log_retention_days: get_i64(
                stored,
                "log_retention_days",
                "LOG_RETENTION_DAYS",
                d.log_retention_days,
            ),
            autonomous_enabled: get_bool(
                stored,
                "autonomous_enabled",
                "AUTONOMOUS_ENABLED",
                d.autonomous_enabled,
            ),
            autonomous_attacks_enabled: get_bool(
                stored,
                "autonomous_attacks_enabled",
                "AUTONOMOUS_ATTACKS_ENABLED",
                d.autonomous_attacks_enabled,
            ),
            autonomous_interval_secs: get_u64(
                stored,
                "autonomous_interval_secs",
                "AUTONOMOUS_INTERVAL_SECS",
                d.autonomous_interval_secs,
            ),
            opsec_quiet: get_bool(stored, "opsec_quiet", "OPSEC_QUIET", d.opsec_quiet),
            opsec_jitter_ms: get_u64(stored, "opsec_jitter_ms", "OPSEC_JITTER_MS", d.opsec_jitter_ms),
            spray_lockout_buffer: get_u64(
                stored,
                "spray_lockout_buffer",
                "SPRAY_LOCKOUT_BUFFER",
                d.spray_lockout_buffer,
            ),
            device_name: get_string(stored, "device_name", "DEVICE_NAME", &d.device_name),
        }
    }
}

// ── Global snapshot ─────────────────────────────────────────────────────────

static SETTINGS: OnceCell<RwLock<Settings>> = OnceCell::new();

/// Install the initial snapshot. Safe to call once at startup.
pub fn init(s: Settings) {
    match SETTINGS.get() {
        Some(lock) => {
            if let Ok(mut guard) = lock.write() {
                *guard = s;
            }
        }
        None => {
            let _ = SETTINGS.set(RwLock::new(s));
        }
    }
}

/// Current settings snapshot. Returns defaults if not yet initialized.
pub fn current() -> Settings {
    SETTINGS
        .get()
        .and_then(|lock| lock.read().ok().map(|g| g.clone()))
        .unwrap_or_default()
}

/// Re-resolve settings from the DB and swap in the new snapshot.
pub async fn reload(pool: &SqlitePool) {
    let fresh = Settings::load(pool).await;
    init(fresh);
}

// ── Log-level hook ──────────────────────────────────────────────────────────
// The binary registers a closure (capturing the tracing reload handle) so the
// Settings UI can change verbosity live without this module depending on
// tracing-subscriber's generic handle types.

type LogSetter = Box<dyn Fn(&str) + Send + Sync>;
static LOG_SETTER: OnceCell<LogSetter> = OnceCell::new();

/// Register the log-level apply hook (called once from `main`).
pub fn register_log_setter(f: LogSetter) {
    let _ = LOG_SETTER.set(f);
}

/// Apply a new log level (e.g. "debug", "info"). No-op if no hook is registered.
pub fn set_log_level(level: &str) {
    if let Some(f) = LOG_SETTER.get() {
        f(level);
    }
}

// ── Value resolution helpers ────────────────────────────────────────────────

/// Coerce a stored JSON value into a string form so numbers/bools set via the
/// key-value config table (which stringifies) parse uniformly.
fn stored_str(stored: &Value, key: &str) -> Option<String> {
    match stored.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(b)) => Some(b.to_string()),
        _ => None,
    }
}

fn get_usize(stored: &Value, key: &str, env: &str, default: usize) -> usize {
    stored_str(stored, key)
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| std::env::var(env).ok().and_then(|s| s.trim().parse().ok()))
        .unwrap_or(default)
}

fn get_u64(stored: &Value, key: &str, env: &str, default: u64) -> u64 {
    stored_str(stored, key)
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| std::env::var(env).ok().and_then(|s| s.trim().parse().ok()))
        .unwrap_or(default)
}

fn get_i64(stored: &Value, key: &str, env: &str, default: i64) -> i64 {
    stored_str(stored, key)
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| std::env::var(env).ok().and_then(|s| s.trim().parse().ok()))
        .unwrap_or(default)
}

fn get_bool(stored: &Value, key: &str, env: &str, default: bool) -> bool {
    let parse = |s: String| match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    };
    stored_str(stored, key)
        .and_then(parse)
        .or_else(|| std::env::var(env).ok().and_then(parse))
        .unwrap_or(default)
}

fn get_string(stored: &Value, key: &str, env: &str, default: &str) -> String {
    stored_str(stored, key)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var(env).ok().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| default.to_string())
}

fn get_opt_string(stored: &Value, key: &str, env: &str) -> Option<String> {
    stored_str(stored, key)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var(env).ok().filter(|s| !s.trim().is_empty()))
}

/// Accept fallback ports as a JSON array of numbers, or a comma/space separated string.
fn get_ports(stored: &Value, key: &str, default: Vec<u16>) -> Vec<u16> {
    match stored.get(key) {
        Some(Value::Array(arr)) => {
            let ports: Vec<u16> = arr
                .iter()
                .filter_map(|v| v.as_u64().and_then(|n| u16::try_from(n).ok()))
                .collect();
            if ports.is_empty() { default } else { ports }
        }
        Some(Value::String(s)) => {
            let ports: Vec<u16> = s
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|t| !t.is_empty())
                .filter_map(|t| t.parse::<u16>().ok())
                .collect();
            if ports.is_empty() { default } else { ports }
        }
        _ => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn from_stored_overrides_defaults_and_coerces_types() {
        // Values may arrive as numbers, strings, or bools from the key-value table.
        let stored = json!({
            "max_scan_concurrency": 123,
            "port_scan_timeout_ms": "350",
            "autonomous_enabled": true,
            "log_level": "debug",
            "fallback_ports": [22, 80, 443]
        });
        let s = Settings::from_stored(&stored);

        assert_eq!(s.max_scan_concurrency, 123);
        assert_eq!(s.port_scan_timeout_ms, 350); // string coerced to number
        assert!(s.autonomous_enabled);
        assert_eq!(s.log_level, "debug");
        assert_eq!(s.fallback_ports, vec![22, 80, 443]);
    }

    #[test]
    fn from_stored_falls_back_to_defaults_when_absent() {
        let s = Settings::from_stored(&json!({}));
        let d = Settings::default();
        assert_eq!(s.max_discover_threads, d.max_discover_threads);
        assert!(!s.autonomous_enabled);
        assert_eq!(s.fallback_ports, d.fallback_ports);
    }
}
