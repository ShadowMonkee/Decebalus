-- Change-detection timeline. One row per detected change to a host, produced by
-- upsert_host_tracked when a host record transitions (new host, up/down, a newly
-- opened port, or a newly detected vulnerability).
CREATE TABLE IF NOT EXISTS host_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    host_ip     TEXT NOT NULL,
    event_type  TEXT NOT NULL,   -- host_new | host_up | host_down | port_opened | vuln_new
    detail      TEXT,            -- port number, CVE id, hostname, etc.
    severity    TEXT             -- populated for vuln_new
);

CREATE INDEX idx_host_events_created ON host_events(created_at DESC);
CREATE INDEX idx_host_events_host ON host_events(host_ip);
