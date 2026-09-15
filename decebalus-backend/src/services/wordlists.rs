//! Bundled + custom wordlists for the brute-force / discovery modules.
//!
//! Every dictionary ships with the app: the vendored SecLists subset (Passwords,
//! Usernames, Discovery) lives under `assets/seclists/` and is registered in the DB
//! on first boot. There are no runtime downloads — the app is fully self-contained
//! and offline. Users can additionally save their own pasted lists (`custom`).
//!
//! Seeding is idempotent: only files not already registered are read and inserted,
//! so after the first boot it is cheap. `main` spawns it in the background so a
//! large first-time scan never blocks server startup.

use crate::db::repository;
use crate::models::Wordlist;
use sqlx::SqlitePool;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Root of the shipped SecLists subset (relative to the process working directory).
const SECLISTS_DIR: &str = "assets/seclists";
/// Where user-saved custom lists are written.
const CUSTOM_DIR: &str = "data/wordlists/custom";

/// Map a shipped list's path to one of the module-facing categories.
fn category_for(path: &str) -> Option<&'static str> {
    if path.contains("/Passwords/") {
        Some("password")
    } else if path.contains("/Usernames/") {
        Some("username")
    } else if path.contains("/Discovery/") {
        Some("discovery")
    } else {
        None
    }
}

fn count_entries(content: &str) -> i64 {
    content.lines().filter(|l| !l.trim().is_empty()).count() as i64
}

/// Recursively collect every `*.txt` under `root`. Synchronous — run in
/// `spawn_blocking` so the directory walk doesn't stall the async runtime.
fn collect_txt(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read_dir) = std::fs::read_dir(&dir) else { continue };
        for entry in read_dir.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("txt") {
                out.push(p);
            }
        }
    }
    out
}

/// Register every shipped SecLists wordlist as a `bundled` entry. Idempotent and
/// safe to call on every startup: it prunes stale bundled rows (files that moved or
/// were removed) and inserts only lists not already registered.
pub async fn seed_bundled(pool: &SqlitePool) {
    // Custom-list directory is always needed for save_custom.
    let _ = tokio::fs::create_dir_all(CUSTOM_DIR).await;

    let root = Path::new(SECLISTS_DIR);
    if !root.exists() {
        tracing::warn!(
            "[wordlists] {} not found — no bundled wordlists registered. Ship the \
             SecLists folder alongside the binary.",
            SECLISTS_DIR
        );
        return;
    }

    // Prune stale bundled rows and remember which files are already registered so
    // we never re-read a 1 GB tree on subsequent boots.
    let existing = repository::list_wordlists(pool).await.unwrap_or_default();
    let mut known: HashSet<String> = HashSet::new();
    for wl in &existing {
        let stale = wl.source == "bundled"
            && (!Path::new(&wl.file_path).exists() || !wl.file_path.starts_with(SECLISTS_DIR));
        if stale {
            let _ = repository::delete_wordlist(pool, &wl.id).await;
        } else {
            known.insert(wl.file_path.clone());
        }
    }

    let root_buf = root.to_path_buf();
    let files = tokio::task::spawn_blocking(move || collect_txt(&root_buf))
        .await
        .unwrap_or_default();

    let total = files.len();
    let mut added = 0usize;
    for path in files {
        let path_str = path.to_string_lossy().to_string();
        if known.contains(&path_str) {
            continue;
        }
        let Some(category) = category_for(&path_str) else { continue };
        let content = match tokio::fs::read_to_string(&path).await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("[wordlists] skipping {}: {}", path_str, e);
                continue;
            }
        };
        // Name = path relative to the seclists root, e.g. "Passwords/Common-Credentials/…".
        let name = path
            .strip_prefix(SECLISTS_DIR)
            .unwrap_or(&path)
            .to_string_lossy()
            .trim_start_matches('/')
            .to_string();
        let wl = Wordlist::new(
            name,
            category.to_string(),
            "bundled".to_string(),
            path_str,
            count_entries(&content),
            content.len() as i64,
        );
        if repository::insert_wordlist(pool, &wl).await.is_ok() {
            added += 1;
        }
    }

    if added > 0 {
        tracing::info!(
            "[wordlists] Registered {} new bundled wordlist(s) ({} total on disk)",
            added,
            total
        );
    } else {
        tracing::info!("[wordlists] Bundled wordlists up to date ({} on disk)", total);
    }
}

/// Save a user-pasted list under a given name so it can be reselected later from the
/// Attacks tab instead of being thrown away after one job.
pub async fn save_custom(
    pool: &SqlitePool,
    name: &str,
    category: &str,
    content: &str,
) -> Result<Wordlist, String> {
    if name.trim().is_empty() {
        return Err("Name is required".to_string());
    }
    if content.trim().is_empty() {
        return Err("List content is empty".to_string());
    }
    if !["username", "password", "discovery"].contains(&category) {
        return Err(format!("Invalid category: {category}"));
    }

    tokio::fs::create_dir_all(CUSTOM_DIR).await.map_err(|e| e.to_string())?;
    let path = format!("{CUSTOM_DIR}/{}.txt", uuid::Uuid::new_v4());
    tokio::fs::write(&path, content)
        .await
        .map_err(|e| format!("Failed to write {path}: {e}"))?;

    let wl = Wordlist::new(
        name.to_string(),
        category.to_string(),
        "custom".to_string(),
        path,
        count_entries(content),
        content.len() as i64,
    );
    repository::insert_wordlist(pool, &wl).await.map_err(|e| e.to_string())?;
    Ok(wl)
}

/// Delete a saved wordlist. Refuses bundled entries — they're re-seeded on every boot.
pub async fn delete(pool: &SqlitePool, id: &str) -> Result<(), String> {
    let wl = repository::get_wordlist(pool, id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Wordlist not found".to_string())?;
    if wl.source == "bundled" {
        return Err("Bundled wordlists cannot be deleted".to_string());
    }
    let _ = tokio::fs::remove_file(&wl.file_path).await;
    repository::delete_wordlist(pool, id).await.map_err(|e| e.to_string())
}
