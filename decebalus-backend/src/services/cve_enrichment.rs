use chrono::Utc;
use sqlx::SqlitePool;
use tokio::time::{sleep, Duration};
use crate::db::repository;
use crate::models::CveDetail;

const NVD_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
/// NVD's public rate limits are per rolling 30-second window: ~5 requests without an
/// API key, ~50 with one. We space requests a little slower than the hard limit to
/// stay safe and avoid the 403/429 responses that previously emptied enrichment.
const NVD_RATE_MS_NO_KEY: u64 = 6_000; // ~5 req / 30s
const NVD_RATE_MS_WITH_KEY: u64 = 600; // ~50 req / 30s

/// Optional NVD API key (env `NVD_API_KEY`). When set, requests carry the `apiKey`
/// header and the faster cadence is used.
fn nvd_api_key() -> Option<String> {
    // Prefer the settings-resolved key (which already merges the env var); fall back
    // to the raw env var in case settings were never initialized (e.g. some tests).
    crate::settings::current()
        .nvd_api_key
        .or_else(|| {
            std::env::var("NVD_API_KEY")
                .ok()
                .filter(|k| !k.trim().is_empty())
        })
}

/// Delay between successive NVD requests, chosen by whether an API key is configured.
fn nvd_rate_ms() -> u64 {
    if nvd_api_key().is_some() {
        NVD_RATE_MS_WITH_KEY
    } else {
        NVD_RATE_MS_NO_KEY
    }
}

pub struct CveEnrichment;

impl CveEnrichment {
    /// Return enriched detail for a single CVE ID.
    ///
    /// Checks the local DB cache first; falls back to the NVD API on cache miss.
    /// The fetched record is cached so subsequent lookups are instant.
    pub async fn get(pool: &SqlitePool, cve_id: &str) -> Option<CveDetail> {
        // Cache hit
        if let Ok(Some(detail)) = repository::get_cve_detail(pool, cve_id).await {
            return Some(detail);
        }
        // Cache miss — fetch from NVD
        match Self::fetch_nvd(cve_id).await {
            Ok(detail) => {
                let _ = repository::upsert_cve_detail(pool, &detail).await;
                Some(detail)
            }
            Err(e) => {
                tracing::warn!("[cve] Failed to fetch {} from NVD: {}", cve_id, e);
                None
            }
        }
    }

    /// Enrich every CVE ID that appears in host vulnerability records but has
    /// no cached detail yet.  Respects the NVD rate limit.
    ///
    /// Designed to run in a background task — individual fetch failures are
    /// logged and skipped so one bad CVE ID doesn't abort the whole batch.
    /// Pass `job_id` to link progress logs to a specific job record.
    pub async fn enrich_all_unenriched(pool: &SqlitePool, job_id: Option<&str>) {
        let ids = match repository::get_unenriched_cve_ids(pool).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("[cve] Could not query unenriched CVEs: {}", e);
                let _ = repository::add_log(pool, "WARN", "cve_enrichment", Some("enrich_all_unenriched"), job_id, &format!("Could not query unenriched CVEs: {}", e)).await;
                return;
            }
        };

        if ids.is_empty() {
            // Distinguish "all cached" from "no vuln data yet" for a useful diagnostic.
            let host_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM hosts")
                .fetch_one(pool)
                .await
                .unwrap_or(0);
            let cached_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM cve_details")
                .fetch_one(pool)
                .await
                .unwrap_or(0);
            let msg = if host_count == 0 {
                "No hosts discovered yet — run a Discovery scan first, then an nmap-scan to detect vulnerabilities.".to_string()
            } else if cached_count > 0 {
                format!("All discovered CVEs are already cached ({} record(s) in local DB).", cached_count)
            } else {
                format!(
                    "No CVEs found across {} host(s). Ensure nmap is installed with the vulners script (`nmap --script-updatedb`) and run an nmap-scan.",
                    host_count
                )
            };
            tracing::info!("[cve] {}", msg);
            let _ = repository::add_log(pool, "INFO", "cve_enrichment", Some("enrich_all_unenriched"), job_id, &msg).await;
            return;
        }

        let rate_ms = nvd_rate_ms();
        let key_note = if nvd_api_key().is_some() {
            "using NVD_API_KEY (fast cadence)"
        } else {
            "no NVD_API_KEY set (slow cadence ~1 req/6s; set NVD_API_KEY to speed up)"
        };
        let msg = format!(
            "[cve] Starting enrichment — {} CVE(s) to fetch from NVD, {}",
            ids.len(),
            key_note
        );
        tracing::info!("{}", msg);
        let _ = repository::add_log(pool, "INFO", "cve_enrichment", Some("enrich_all_unenriched"), job_id, &msg).await;

        let mut succeeded = 0usize;
        let mut failed = 0usize;

        for (i, id) in ids.iter().enumerate() {
            let progress = format!("({}/{})", i + 1, ids.len());
            tracing::info!("[cve] Fetching {} {}", id, progress);
            let _ = repository::add_log(pool, "INFO", "cve_enrichment", Some("enrich_all_unenriched"), job_id, &format!("Fetching {} {}", id, progress)).await;

            match Self::fetch_nvd(id).await {
                Ok(detail) => {
                    if let Err(e) = repository::upsert_cve_detail(pool, &detail).await {
                        let msg = format!("DB write failed for {} {}: {}", id, progress, e);
                        tracing::warn!("[cve] {}", msg);
                        let _ = repository::add_log(pool, "WARN", "cve_enrichment", Some("enrich_all_unenriched"), job_id, &msg).await;
                        failed += 1;
                    } else {
                        let score_str = detail.cvss_v3_score
                            .map(|s| format!("CVSS v3: {:.1}", s))
                            .or_else(|| detail.cvss_v2_score.map(|s| format!("CVSS v2: {:.1}", s)))
                            .unwrap_or_else(|| "no score".to_string());
                        let msg = format!("Cached {} {} | {} | {}", id, progress, detail.cvss_v3_severity.as_deref().unwrap_or("NO_SCORE"), score_str);
                        tracing::info!("[cve] {}", msg);
                        let _ = repository::add_log(pool, "INFO", "cve_enrichment", Some("enrich_all_unenriched"), job_id, &msg).await;
                        succeeded += 1;
                    }
                }
                Err(e) => {
                    let msg = format!("Fetch failed for {} {}: {}", id, progress, e);
                    tracing::warn!("[cve] {}", msg);
                    let _ = repository::add_log(pool, "WARN", "cve_enrichment", Some("enrich_all_unenriched"), job_id, &msg).await;
                    failed += 1;
                }
            }
            // Rate-limit between requests
            if i + 1 < ids.len() {
                sleep(Duration::from_millis(rate_ms)).await;
            }
        }

        let summary = format!("Enrichment complete — {}/{} CVE(s) cached, {} failed", succeeded, ids.len(), failed);
        tracing::info!("[cve] {}", summary);
        let _ = repository::add_log(pool, "INFO", "cve_enrichment", Some("enrich_all_unenriched"), job_id, &summary).await;
    }

    /// Fetch a single CVE record from the NVD 2.0 API.
    async fn fetch_nvd(cve_id: &str) -> Result<CveDetail, String> {
        let url = format!("{}?cveId={}", NVD_API, cve_id);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let mut request = client.get(&url).header("Accept", "application/json");
        // NVD grants a higher rate limit to requests carrying a valid API key.
        if let Some(key) = nvd_api_key() {
            request = request.header("apiKey", key);
        }

        let resp = request
            .send()
            .await
            .map_err(|e| format!("NVD request failed: {}", e))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(format!("CVE {} not found in NVD", cve_id));
        }
        if !resp.status().is_success() {
            return Err(format!("NVD returned HTTP {}", resp.status()));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("NVD response parse error: {}", e))?;

        Self::parse_nvd_response(cve_id, &json)
            .ok_or_else(|| format!("NVD response for {} had unexpected shape", cve_id))
    }

    /// Parse an NVD 2.0 CVE response into a `CveDetail`.
    fn parse_nvd_response(cve_id: &str, json: &serde_json::Value) -> Option<CveDetail> {
        let cve = json
            .get("vulnerabilities")?
            .get(0)?
            .get("cve")?;

        // English description
        let description = cve
            .get("descriptions")?
            .as_array()?
            .iter()
            .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en"))
            .and_then(|d| d.get("value")?.as_str())
            .unwrap_or("")
            .to_string();

        // CVSS v3 (prefer v3.1, fall back to v3.0)
        let metrics = cve.get("metrics");
        let (cvss_v3_score, cvss_v3_severity) = metrics
            .and_then(|m| {
                m.get("cvssMetricV31")
                    .or_else(|| m.get("cvssMetricV30"))
            })
            .and_then(|arr| arr.get(0))
            .and_then(|entry| {
                let data = entry.get("cvssData")?;
                let score    = data.get("baseScore")?.as_f64();
                let severity = data.get("baseSeverity")?.as_str().map(str::to_string);
                Some((score, severity))
            })
            .unwrap_or((None, None));

        // CVSS v2
        let (cvss_v2_score, cvss_v2_severity) = metrics
            .and_then(|m| m.get("cvssMetricV2"))
            .and_then(|arr| arr.get(0))
            .and_then(|entry| {
                let score    = entry.get("cvssData")?.get("baseScore")?.as_f64()?;
                // v2 severity sits at the metric level, not inside cvssData
                let severity = entry.get("baseSeverity")?.as_str().map(str::to_string);
                Some((Some(score), severity))
            })
            .unwrap_or((None, None));

        let published_at = cve
            .get("published")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let references: Vec<String> = cve
            .get("references")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| r.get("url")?.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        Some(CveDetail {
            cve_id:       cve_id.to_string(),
            description,
            cvss_v3_score,
            cvss_v3_severity,
            cvss_v2_score,
            cvss_v2_severity,
            published_at,
            references,
            fetched_at:   Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_nvd_response_extracts_v3_score_desc_and_refs() {
        let body = json!({
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-1234",
                    "descriptions": [
                        { "lang": "es", "value": "Una vulnerabilidad." },
                        { "lang": "en", "value": "A test vulnerability." }
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": { "baseScore": 9.8, "baseSeverity": "CRITICAL" }
                        }]
                    },
                    "published": "2021-01-01T00:00:00.000",
                    "references": [
                        { "url": "https://example.com/a" },
                        { "url": "https://example.com/b" }
                    ]
                }
            }]
        });

        let d = CveEnrichment::parse_nvd_response("CVE-2021-1234", &body)
            .expect("should parse");
        assert_eq!(d.cve_id, "CVE-2021-1234");
        assert_eq!(d.description, "A test vulnerability."); // English preferred
        assert_eq!(d.cvss_v3_score, Some(9.8));
        assert_eq!(d.cvss_v3_severity.as_deref(), Some("CRITICAL"));
        assert_eq!(d.references.len(), 2);
        assert_eq!(d.published_at.as_deref(), Some("2021-01-01T00:00:00.000"));
    }

    #[test]
    fn parse_nvd_response_none_on_unexpected_shape() {
        let body = json!({ "unexpected": true });
        assert!(CveEnrichment::parse_nvd_response("CVE-0000-0000", &body).is_none());
    }
}
