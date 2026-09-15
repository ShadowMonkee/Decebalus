-- Saved wordlists for brute-force modules: a small bundled set (vendored SecLists
-- subset), lists downloaded on demand from SecLists, and user-pasted custom lists.
CREATE TABLE IF NOT EXISTS wordlists (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,      -- 'username' | 'password' | 'discovery'
    source      TEXT NOT NULL,      -- 'bundled' | 'downloaded' | 'custom'
    file_path   TEXT NOT NULL,
    entry_count INTEGER NOT NULL DEFAULT 0,
    size_bytes  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX idx_wordlists_category ON wordlists(category);
