//! Tool-dependency doctor. Decebalus orchestrates external tools rather than
//! reimplementing them, so this reports which are present on `PATH` and how to
//! install the missing ones. Run with: `decebalus-backend doctor`.

use std::path::Path;

/// One external tool Decebalus can drive, and whether it is installed.
pub struct ToolStatus {
    pub name: &'static str,
    pub present: bool,
    pub purpose: &'static str,
    pub install: &'static str,
}

/// The tools Decebalus knows how to use, in rough order of importance.
pub fn check_tools() -> Vec<ToolStatus> {
    // (binary candidates, purpose, install hint)
    let specs: &[(&[&str], &str, &str)] = &[
        (&["nmap"], "port/service scanning, OS & vuln detection", "apt install nmap"),
        (&["nxc", "netexec"], "AD enumeration, spray, roasting, BloodHound", "pipx install netexec"),
        (&["smbclient"], "SMB brute force fallback", "apt install smbclient"),
        (&["certipy"], "ADCS misconfiguration checks (ESC1–ESC8)", "pipx install certipy-ad"),
        (&["xfreerdp", "xfreerdp3"], "RDP brute force (NLA)", "apt install freerdp2-x11"),
        (&["bloodhound-python"], "alternate BloodHound collector", "pipx install bloodhound"),
        (&["ntlmrelayx.py"], "NTLM relay (operator-run, from findings)", "pipx install impacket"),
        (&["responder"], "LLMNR/NBT-NS poisoning (operator-run)", "apt install responder"),
        (&["hashcat"], "offline cracking of roasted hashes", "apt install hashcat"),
    ];

    specs
        .iter()
        .map(|(cands, purpose, install)| {
            let present = cands.iter().any(|c| on_path(c));
            ToolStatus { name: cands[0], present, purpose, install }
        })
        .collect()
}

/// True if `name` exists as a file in any `PATH` directory.
fn on_path(name: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else { return false };
    std::env::split_paths(&path).any(|dir| {
        let p: &Path = dir.as_path();
        p.join(name).is_file()
    })
}

/// Print a human-readable report to stdout. Core tools (nmap, nxc) missing is
/// called out prominently.
pub fn print_report() {
    let tools = check_tools();
    println!("Decebalus tool doctor\n=====================");
    let mut missing_core = false;
    for t in &tools {
        let mark = if t.present { "✓" } else { "✗" };
        println!("  {} {:<16} {}", mark, t.name, t.purpose);
        if !t.present {
            println!("      └─ install: {}", t.install);
            if matches!(t.name, "nmap" | "nxc") {
                missing_core = true;
            }
        }
    }
    let present = tools.iter().filter(|t| t.present).count();
    println!("\n{}/{} tools available.", present, tools.len());
    if missing_core {
        println!("⚠ Core tooling missing — install nmap and NetExec for the AD opener to work.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_tools_covers_the_core_stack() {
        let tools = check_tools();
        for expected in ["nmap", "nxc", "certipy"] {
            assert!(tools.iter().any(|t| t.name == expected), "missing {expected}");
        }
        // Determinism: purpose/install hints are always populated.
        assert!(tools.iter().all(|t| !t.purpose.is_empty() && !t.install.is_empty()));
    }
}
