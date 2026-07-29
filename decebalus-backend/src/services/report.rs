//! Self-contained HTML report generation (no external assets).

use std::collections::HashMap;

use crate::models::{Credential, CveDetail, Finding, Host, HostEvent, HostStatus};

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let kept: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{}…", kept)
    }
}

/// Resolve a vulnerability's severity, preferring enriched NVD data over the raw
/// value from the vulners script.
fn vuln_severity(id: &str, fallback: &str, cves: &HashMap<String, CveDetail>) -> String {
    cves.get(id)
        .and_then(|d| {
            d.cvss_v3_severity
                .clone()
                .or_else(|| d.cvss_v2_severity.clone())
        })
        .unwrap_or_else(|| fallback.to_string())
        .to_uppercase()
}

fn sev_class(sev: &str) -> &'static str {
    match sev.to_uppercase().as_str() {
        "CRITICAL" => "crit",
        "HIGH" => "high",
        "MEDIUM" => "med",
        "LOW" => "low",
        _ => "other",
    }
}

fn status_label(s: &HostStatus) -> &'static str {
    match s {
        HostStatus::Up => "Up",
        HostStatus::Down => "Down",
        HostStatus::Unknown => "Unknown",
    }
}

/// Render a full HTML security report. Pure function → unit-testable.
pub fn render_html(
    hosts: &[Host],
    cves: &HashMap<String, CveDetail>,
    events: &[HostEvent],
    findings: &[Finding],
    creds: &[Credential],
    device_name: &str,
    generated_at: &str,
) -> String {
    let total = hosts.len();
    let up = hosts.iter().filter(|h| h.status == HostStatus::Up).count();
    let down = hosts.iter().filter(|h| h.status == HostStatus::Down).count();
    let open_ports: usize = hosts
        .iter()
        .map(|h| h.ports.iter().filter(|p| p.status == "open").count())
        .sum();

    let (mut crit, mut high, mut med, mut low, mut other) = (0, 0, 0, 0, 0);
    for h in hosts {
        for v in &h.vulnerabilities {
            match vuln_severity(&v.id, &v.severity, cves).as_str() {
                "CRITICAL" => crit += 1,
                "HIGH" => high += 1,
                "MEDIUM" => med += 1,
                "LOW" => low += 1,
                _ => other += 1,
            }
        }
    }
    let total_vulns = crit + high + med + low + other;

    let mut h = String::new();
    h.push_str("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    h.push_str(&format!("<title>Decebalus Report — {}</title>", esc(device_name)));
    h.push_str("<style>");
    h.push_str(CSS);
    h.push_str("</style></head><body>");

    h.push_str(&format!(
        "<header><h1>Decebalus Report</h1><p class=\"muted\">{} · generated {}</p></header>",
        esc(device_name),
        esc(generated_at)
    ));

    // Summary tiles
    h.push_str("<section class=\"summary\">");
    for (n, label) in [
        (total, "Hosts"),
        (up, "Up"),
        (down, "Down"),
        (open_ports, "Open ports"),
        (total_vulns, "Vulnerabilities"),
    ] {
        h.push_str(&format!(
            "<div class=\"stat\"><span class=\"n\">{}</span><span class=\"l\">{}</span></div>",
            n, label
        ));
    }
    h.push_str("</section>");

    // Severity rollup
    h.push_str("<section><h2>Vulnerabilities by severity</h2><div class=\"sev\">");
    for (label, n, cls) in [
        ("Critical", crit, "crit"),
        ("High", high, "high"),
        ("Medium", med, "med"),
        ("Low", low, "low"),
        ("Other", other, "other"),
    ] {
        h.push_str(&format!("<span class=\"chip {}\">{}: {}</span>", cls, label, n));
    }
    h.push_str("</div></section>");

    // Findings — the ranked next-moves / results (headline of an engagement report).
    let active_findings: Vec<&Finding> = findings.iter().filter(|f| f.status != "dismissed").collect();
    h.push_str("<section><h2>Findings &amp; next moves</h2>");
    if active_findings.is_empty() {
        h.push_str("<p class=\"muted\">No findings recorded.</p>");
    } else {
        h.push_str("<table><thead><tr><th>Score</th><th>Severity</th><th>Finding</th><th>Status</th><th>Detail</th></tr></thead><tbody>");
        for f in active_findings {
            let detail = match &f.suggested_command {
                Some(cmd) => format!("{}<br><code>{}</code>", esc(&truncate(&f.rationale, 180)), esc(cmd)),
                None => esc(&truncate(&f.rationale, 220)),
            };
            h.push_str(&format!(
                "<tr><td>{}</td><td><span class=\"sevtag {}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                f.value_score,
                sev_class(&f.severity.to_uppercase()),
                esc(&f.severity.to_uppercase()),
                esc(&f.title),
                esc(&f.status),
                detail
            ));
        }
        h.push_str("</tbody></table>");
    }
    h.push_str("</section>");

    // Credentials obtained during the engagement.
    if !creds.is_empty() {
        h.push_str("<section><h2>Credentials obtained</h2><table><thead><tr><th>Domain</th><th>Username</th><th>Type</th><th>Privilege</th><th>Validated</th></tr></thead><tbody>");
        for c in creds {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(if c.domain.is_empty() { "—" } else { &c.domain }),
                esc(&c.username),
                esc(&c.secret_type),
                esc(&c.privilege),
                if c.validated { "yes" } else { "no" }
            ));
        }
        h.push_str("</tbody></table></section>");
    }

    // Per-host findings
    h.push_str("<section><h2>Hosts</h2>");
    if hosts.is_empty() {
        h.push_str("<p class=\"muted\">No hosts discovered.</p>");
    }
    for host in hosts {
        h.push_str("<div class=\"host\">");
        h.push_str(&format!(
            "<h3>{} <span class=\"muted\">{}</span> <span class=\"status {}\">{}</span></h3>",
            esc(&host.ip),
            esc(host.hostname.as_deref().unwrap_or("")),
            sev_class(""), // neutral
            status_label(&host.status)
        ));
        if let Some(os) = &host.os {
            h.push_str(&format!("<p class=\"muted\">OS: {}</p>", esc(os)));
        }

        let open: Vec<_> = host.ports.iter().filter(|p| p.status == "open").collect();
        if !open.is_empty() {
            h.push_str("<table><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th></tr></thead><tbody>");
            for p in open {
                h.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    p.number,
                    esc(&p.protocol),
                    esc(p.service.as_deref().unwrap_or("—")),
                    esc(p.version.as_deref().unwrap_or("—"))
                ));
            }
            h.push_str("</tbody></table>");
        }

        if !host.vulnerabilities.is_empty() {
            h.push_str("<table><thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr></thead><tbody>");
            for v in &host.vulnerabilities {
                let detail = cves.get(&v.id);
                let sev = vuln_severity(&v.id, &v.severity, cves);
                let cvss = detail
                    .and_then(|d| d.cvss_v3_score.or(d.cvss_v2_score))
                    .map(|s| format!("{:.1}", s))
                    .unwrap_or_else(|| "—".to_string());
                let desc = detail
                    .map(|d| d.description.clone())
                    .filter(|d| !d.is_empty())
                    .unwrap_or_else(|| v.description.clone());
                h.push_str(&format!(
                    "<tr><td>{}</td><td><span class=\"sevtag {}\">{}</span></td><td>{}</td><td>{}</td></tr>",
                    esc(&v.id),
                    sev_class(&sev),
                    esc(&sev),
                    cvss,
                    esc(&truncate(&desc, 220))
                ));
            }
            h.push_str("</tbody></table>");
        }
        h.push_str("</div>");
    }
    h.push_str("</section>");

    // Recent changes
    if !events.is_empty() {
        h.push_str("<section><h2>Recent changes</h2><table><thead><tr><th>When</th><th>Event</th><th>Host</th><th>Detail</th></tr></thead><tbody>");
        for e in events {
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&e.created_at),
                esc(&e.event_type),
                esc(&e.host_ip),
                esc(e.detail.as_deref().unwrap_or("—"))
            ));
        }
        h.push_str("</tbody></table></section>");
    }

    h.push_str("<footer class=\"muted\">Generated by Decebalus. Authorized use only.</footer>");
    h.push_str("</body></html>");
    h
}

const CSS: &str = "\
:root{color-scheme:light dark}\
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:2rem;max-width:1000px;margin:0 auto;line-height:1.5}\
header h1{margin:0 0 .25rem}\
.muted{color:#888;font-size:.9rem}\
h2{border-bottom:1px solid #8884;padding-bottom:.3rem;margin-top:2rem}\
.summary{display:flex;flex-wrap:wrap;gap:1rem;margin-top:1rem}\
.stat{border:1px solid #8884;border-radius:8px;padding:.8rem 1.2rem;display:flex;flex-direction:column;min-width:90px}\
.stat .n{font-size:1.8rem;font-weight:700}\
.stat .l{font-size:.8rem;color:#888}\
.sev{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.5rem}\
.chip,.sevtag{padding:.15rem .55rem;border-radius:4px;font-size:.8rem;font-weight:600}\
.crit{background:#b3261e;color:#fff}.high{background:#c26a1a;color:#fff}.med{background:#2b6cb0;color:#fff}.low{background:#4a5568;color:#fff}.other{background:#8884;color:inherit}\
.host{border:1px solid #8884;border-radius:8px;padding:1rem;margin:1rem 0}\
.host h3{margin:.2rem 0 .6rem;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}\
.status{font-size:.75rem;padding:.1rem .5rem;border-radius:4px;background:#8884}\
table{width:100%;border-collapse:collapse;margin:.6rem 0;font-size:.88rem}\
th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #8883}\
th{color:#888;font-weight:600}\
footer{margin-top:2rem;text-align:center}\
";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Host, HostStatus, Port, Vulnerability};

    #[test]
    fn renders_self_contained_html_with_sections() {
        let mut host = Host::new("192.168.1.10".into());
        host.status = HostStatus::Up;
        host.ports = vec![Port {
            number: 22,
            protocol: "tcp".into(),
            status: "open".into(),
            service: Some("ssh".into()),
            version: None,
            cpe: None,
        }];
        host.vulnerabilities = vec![Vulnerability {
            id: "CVE-2023-0001".into(),
            description: "test vuln".into(),
            severity: "HIGH".into(),
        }];

        let cves = HashMap::new();
        let mut finding = crate::models::Finding::new("adcs-esc1:10.0.0.5", "ADCS ESC1 on CA01");
        finding.severity = "critical".into();
        finding.value_score = 90;
        let html = render_html(&[host], &cves, &[], &[finding], &[], "decebalus-01", "2026-07-24T00:00:00Z");

        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("Decebalus Report"));
        assert!(html.contains("192.168.1.10"));
        assert!(html.contains("CVE-2023-0001"));
        assert!(html.contains("ssh"));
        assert!(html.contains("Vulnerabilities by severity"));
        assert!(html.contains("Findings &amp; next moves"));
        assert!(html.contains("ADCS ESC1 on CA01"));
        assert!(html.trim_end().ends_with("</html>"));
    }
}
