-- Jobs table
CREATE TABLE jobs (
    id TEXT PRIMARY KEY NOT NULL,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    results TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_created_at ON jobs(created_at DESC);

-- Hosts table
CREATE TABLE hosts (
    ip TEXT PRIMARY KEY NOT NULL,
    ports TEXT NOT NULL DEFAULT '[]',
    banners TEXT NOT NULL DEFAULT '[]',
    last_seen TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_hosts_last_seen ON hosts(last_seen DESC);

-- Vulnerabilities table (for future use)
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip TEXT NOT NULL,
    port INTEGER,
    vulnerability_name TEXT NOT NULL,
    severity TEXT,
    description TEXT,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (host_ip) REFERENCES hosts(ip) ON DELETE CASCADE
);

CREATE INDEX idx_vulns_host ON vulnerabilities(host_ip);

-- Config table (key-value store)
CREATE TABLE config (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Display status table (single row)
CREATE TABLE display_status (
    id INTEGER PRIMARY KEY DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'idle',
    last_update TEXT NOT NULL DEFAULT 'never',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CHECK (id = 1)
);

-- Insert default display status
INSERT INTO display_status (id, status, last_update) VALUES (1, 'idle', 'never');