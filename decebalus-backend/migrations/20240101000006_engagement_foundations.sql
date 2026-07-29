-- Assumed-breach engagement data model. These four tables give modules and the
-- next-move rule engine shared state to reason over: a scoped engagement, a
-- credential store, generic facts, and ranked findings (the "next moves").
--
-- engagement_id defaults to '' (the implicit global engagement) rather than NULL
-- so the UNIQUE indexes below behave predictably (SQLite treats NULLs as distinct).

-- One engagement = one internal/assumed-breach test. Carries scope + AD context.
CREATE TABLE IF NOT EXISTS engagements (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    scope_cidrs  TEXT NOT NULL DEFAULT '[]',   -- JSON array of CIDR strings (scope-lock)
    domain       TEXT,                         -- AD domain, if known
    dc_ip        TEXT,                          -- domain controller IP, if known
    status       TEXT NOT NULL DEFAULT 'active',-- active | archived
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_engagements_status ON engagements(status);

-- Credential store. Replaces the throwaway "user:pass" strings previously buried
-- in jobs.results, so modules can share and chain credentials across the engagement.
CREATE TABLE IF NOT EXISTS credentials (
    id             TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL DEFAULT '',
    domain         TEXT NOT NULL DEFAULT '',
    username       TEXT NOT NULL,
    secret_type    TEXT NOT NULL DEFAULT 'password', -- password | nt_hash | aes_key | ticket
    secret         TEXT NOT NULL DEFAULT '',
    source_job_id  TEXT,
    validated      INTEGER NOT NULL DEFAULT 0,        -- bool: proven to authenticate somewhere
    valid_on       TEXT NOT NULL DEFAULT '[]',        -- JSON array of "host:service" it works on
    privilege      TEXT NOT NULL DEFAULT 'unknown',   -- unknown | user | admin | da
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(engagement_id, domain, username, secret)
);
CREATE INDEX IF NOT EXISTS idx_credentials_engagement ON credentials(engagement_id);

-- Generic fact store. Modules record observations (SMB signing state, null-session
-- allowed, ADCS present, roastable SPNs, …); the rule engine reads these to produce
-- findings. Kept schemaless (key + JSON value) so new checks need no migration.
CREATE TABLE IF NOT EXISTS facts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id  TEXT NOT NULL DEFAULT '',
    subject_type   TEXT NOT NULL,                     -- host | domain | cred | share
    subject_id     TEXT NOT NULL,                     -- e.g. an IP, a domain FQDN
    key            TEXT NOT NULL,                     -- e.g. smb_signing, null_session
    value          TEXT NOT NULL DEFAULT 'null',      -- JSON value
    source_job_id  TEXT,
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(engagement_id, subject_type, subject_id, key)
);
CREATE INDEX IF NOT EXISTS idx_facts_engagement ON facts(engagement_id);
CREATE INDEX IF NOT EXISTS idx_facts_subject ON facts(subject_type, subject_id);

-- Findings = the ranked "next moves" shown on the war table. Each carries a
-- copy-paste command and, when auto_runnable, a job_type + job_config for one-click run.
CREATE TABLE IF NOT EXISTS findings (
    id                TEXT PRIMARY KEY,
    engagement_id     TEXT NOT NULL DEFAULT '',
    dedup_key         TEXT NOT NULL,                  -- stable key for upsert (e.g. "adcs-esc1:HOST")
    title             TEXT NOT NULL,
    category          TEXT NOT NULL DEFAULT '',       -- enum | attack | exfil | ad
    value_score       INTEGER NOT NULL DEFAULT 0,     -- ranking; higher = more valuable
    severity          TEXT NOT NULL DEFAULT 'info',   -- info | low | medium | high | critical
    rationale         TEXT NOT NULL DEFAULT '',
    suggested_command TEXT,                           -- copy-paste command for the operator
    auto_runnable     INTEGER NOT NULL DEFAULT 0,     -- bool
    job_type          TEXT,                           -- module to enqueue on one-click run
    job_config        TEXT NOT NULL DEFAULT '{}',     -- JSON config for that job
    status            TEXT NOT NULL DEFAULT 'suggested', -- suggested | queued | running | done | dismissed
    evidence          TEXT NOT NULL DEFAULT '{}',     -- JSON refs to facts/creds/hosts
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(engagement_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
