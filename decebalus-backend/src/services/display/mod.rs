//! Status display service.
//!
//! Renders a small "device status" screen (device name/IP, current activity,
//! host + vuln counts, autonomous state). The default [`MockDisplay`] renders to
//! the log so it works on any host; a real Waveshare e-paper driver is provided
//! behind the `hardware` cargo feature and selected automatically when built for
//! the Pi. State is polled every few seconds — appropriate for slow e-ink refresh.

mod mock;
#[cfg(feature = "hardware")]
mod epaper;

pub use mock::MockDisplay;

use std::sync::Arc;
use tokio::time::{sleep, Duration};

use crate::db::repository;
use crate::models::HostStatus;
use crate::services::scanner::NetworkScanner;
use crate::settings;
use crate::state::AppState;

/// Snapshot of what the status display should show.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DisplayState {
    pub device_name: String,
    pub ip: String,
    pub status: String,
    pub hosts_up: usize,
    pub hosts_total: usize,
    pub vulns: usize,
    pub autonomous: bool,
}

impl DisplayState {
    /// Lines suitable for a small text screen (kept short for a 2.13" panel).
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("{}  {}", self.device_name, self.ip),
            format!("Status: {}", truncate(&self.status, 22)),
            format!("Hosts: {}/{}  Vulns: {}", self.hosts_up, self.hosts_total, self.vulns),
            format!("Auto: {}", if self.autonomous { "ON" } else { "off" }),
        ]
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let kept: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{}…", kept)
    }
}

/// A rendering backend for the status display.
pub trait DisplayDriver: Send {
    fn render(&mut self, state: &DisplayState) -> Result<(), String>;
}

pub struct DisplayService;

impl DisplayService {
    pub async fn run(state: Arc<AppState>) {
        let mut driver = make_driver();
        tracing::info!("[display] service started");

        let mut last = DisplayState::default();
        let mut first = true;
        loop {
            let ds = build_state(&state).await;
            if first || ds != last {
                if let Err(e) = driver.render(&ds) {
                    tracing::warn!("[display] render failed: {}", e);
                }
                last = ds;
                first = false;
            }
            // e-ink refreshes slowly; a few seconds is plenty.
            sleep(Duration::from_secs(5)).await;
        }
    }
}

async fn build_state(state: &Arc<AppState>) -> DisplayState {
    let hosts = repository::list_hosts(&state.db).await.unwrap_or_default();
    let hosts_up = hosts.iter().filter(|h| h.status == HostStatus::Up).count();
    let vulns = hosts.iter().map(|h| h.vulnerabilities.len()).sum();

    let status = repository::get_display_status(&state.db)
        .await
        .map(|d| d.status)
        .unwrap_or_else(|_| "idle".to_string());

    let s = settings::current();
    DisplayState {
        device_name: s.device_name,
        ip: NetworkScanner::local_ipv4()
            .map(|i| i.to_string())
            .unwrap_or_else(|| "—".to_string()),
        status,
        hosts_up,
        hosts_total: hosts.len(),
        vulns,
        autonomous: s.autonomous_enabled,
    }
}

#[cfg(feature = "hardware")]
fn make_driver() -> Box<dyn DisplayDriver> {
    match epaper::EpaperDisplay::new() {
        Ok(d) => {
            tracing::info!("[display] using e-paper hardware driver");
            Box::new(d)
        }
        Err(e) => {
            tracing::warn!("[display] e-paper init failed ({e}); falling back to mock");
            Box::new(MockDisplay::new())
        }
    }
}

#[cfg(not(feature = "hardware"))]
fn make_driver() -> Box<dyn DisplayDriver> {
    Box::new(MockDisplay::new())
}
