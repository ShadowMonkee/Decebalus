-- Secrets-at-rest: `secret` now stores AES-256-GCM ciphertext (base64), not the
-- plaintext password/hash/ticket. Encrypting with a random nonce means the same
-- plaintext no longer produces the same `secret` value on every insert, which
-- breaks the old UNIQUE(engagement_id, domain, username, secret) upsert target.
-- Dedup instead on `secret_hash`, a deterministic per-engagement HMAC-SHA256 of
-- the plaintext, computed alongside the ciphertext at write time.
--
-- Existing rows (pre-encryption, plaintext) are carried over with secret_hash = ''
-- since this is pre-production dev data; they stop being usable as valid
-- credentials until re-captured, which is expected for this migration.

CREATE TABLE credentials_new (
    id             TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL DEFAULT '',
    domain         TEXT NOT NULL DEFAULT '',
    username       TEXT NOT NULL,
    secret_type    TEXT NOT NULL DEFAULT 'password',
    secret         TEXT NOT NULL DEFAULT '',
    secret_hash    TEXT NOT NULL DEFAULT '',
    source_job_id  TEXT,
    validated      INTEGER NOT NULL DEFAULT 0,
    valid_on       TEXT NOT NULL DEFAULT '[]',
    privilege      TEXT NOT NULL DEFAULT 'unknown',
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(engagement_id, domain, username, secret_hash)
);

INSERT INTO credentials_new
    (id, engagement_id, domain, username, secret_type, secret, secret_hash, source_job_id, validated, valid_on, privilege, created_at)
SELECT
    id, engagement_id, domain, username, secret_type, secret, '', source_job_id, validated, valid_on, privilege, created_at
FROM credentials;

DROP TABLE credentials;
ALTER TABLE credentials_new RENAME TO credentials;
CREATE INDEX IF NOT EXISTS idx_credentials_engagement ON credentials(engagement_id);
