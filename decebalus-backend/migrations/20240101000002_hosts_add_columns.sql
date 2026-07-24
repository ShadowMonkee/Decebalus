-- Add missing host metadata columns
ALTER TABLE hosts ADD COLUMN os TEXT NULL;
ALTER TABLE hosts ADD COLUMN os_version TEXT NULL;
ALTER TABLE hosts ADD COLUMN device_type TEXT NULL;
ALTER TABLE hosts ADD COLUMN mac_address TEXT NULL;
ALTER TABLE hosts ADD COLUMN hostname TEXT NULL;
ALTER TABLE hosts ADD COLUMN status TEXT NOT NULL DEFAULT 'Unknown';
ALTER TABLE hosts ADD COLUMN first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));
ALTER TABLE hosts ADD COLUMN services TEXT NOT NULL DEFAULT '[]';
ALTER TABLE hosts ADD COLUMN vulnerabilities TEXT NOT NULL DEFAULT '[]';
