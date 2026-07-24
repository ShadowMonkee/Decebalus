-- CVE enrichment cache — populated on demand from the NVD API.
-- Each row caches the NVD record for one CVE ID so subsequent lookups
-- are served locally without hitting the network.
CREATE TABLE IF NOT EXISTS cve_details (
    cve_id            TEXT PRIMARY KEY NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    cvss_v3_score     REAL,
    cvss_v3_severity  TEXT,
    cvss_v2_score     REAL,
    cvss_v2_severity  TEXT,
    published_at      TEXT,
    references_json   TEXT NOT NULL DEFAULT '[]',
    fetched_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX idx_cve_details_severity ON cve_details(cvss_v3_severity);
