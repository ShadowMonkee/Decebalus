-- Jobs table
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY NOT NULL,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    priority INTEGER NOT NULL DEFAULT 1,
    results TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    scheduled_at TEXT
);

CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_created_at ON jobs(created_at DESC);

-- Hosts table
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY NOT NULL,
    ports TEXT NOT NULL DEFAULT '[]',
    banners TEXT NOT NULL DEFAULT '[]',
    last_seen TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_hosts_last_seen ON hosts(last_seen DESC);

-- Vulnerabilities table (for future use)
CREATE TABLE IF NOT EXISTS vulnerabilities (
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
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Display status table (single row)
CREATE TABLE IF NOT EXISTS display_status (
    id INTEGER PRIMARY KEY DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'idle',
    last_update TEXT NOT NULL DEFAULT 'never',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CHECK (id = 1)
);

CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity TEXT NOT NULL DEFAULT 'INFO',
    service TEXT NOT NULL, -- The service invoking the log:decebalus_backend::services::scanner, decebalus_backend::services::job_executor
    module TEXT NULL, -- Is it related to the scanning module, attack module, etc... Useful for future proofing app expansion
    job_id TEXT NULL,
    content TEXT NOT NULL
);

CREATE INDEX idx_logs_created_at ON logs(created_at);
CREATE INDEX idx_logs_job_id ON logs(job_id);
CREATE INDEX idx_logs_level ON logs(severity);
CREATE INDEX idx_logs_service ON logs(service);

-- Insert default display status
INSERT INTO display_status (id, status, last_update) VALUES (1, 'idle', 'never');
