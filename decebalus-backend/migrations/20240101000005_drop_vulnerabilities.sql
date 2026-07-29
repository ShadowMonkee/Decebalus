-- The relational `vulnerabilities` table (created "for future use") was never
-- populated or queried: vulnerabilities are stored as JSON on the hosts row and
-- change events live in host_events. Drop the orphan. (Its index goes with it.)
DROP TABLE IF EXISTS vulnerabilities;
