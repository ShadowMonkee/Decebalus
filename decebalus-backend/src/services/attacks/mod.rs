pub mod ssh_brute;
pub mod ftp_brute;
pub mod file_steal;

pub use ssh_brute::SshBruteForce;
pub use ftp_brute::FtpBruteForce;
pub use file_steal::FileSteal;

use serde_json::Value;

// Pi-specific credential defaults — covers common factory/default credentials.
pub const DEFAULT_USERNAMES: &[&str] = &[
    "root", "pi", "admin", "ubuntu", "user", "raspberry", "test", "guest",
];
pub const DEFAULT_PASSWORDS: &[&str] = &[
    "raspberry", "pi", "admin", "password", "1234", "12345", "root",
    "toor", "pass", "test", "admin123", "default", "letmein", "",
];

/// Load a credential list from the job config. Resolution order:
/// 1. Inline array at `inline_key`
/// 2. File path at `path_key` (one entry per line, # comments stripped)
/// 3. Built-in defaults
pub async fn load_wordlist(
    config: &serde_json::Map<String, Value>,
    inline_key: &str,
    path_key: &str,
    defaults: &[&str],
) -> Vec<String> {
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
