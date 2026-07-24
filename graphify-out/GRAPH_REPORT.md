# Graph Report - Decebalus  (2026-07-24)

## Corpus Check
- 62 files · ~28,036 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 373 nodes · 518 edges · 38 communities (25 shown, 13 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 33 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `4629b3bf`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]

## God Nodes (most connected - your core abstractions)
1. `PortScanner` - 24 edges
2. `DbRepository` - 22 edges
3. `InMemoryRepository` - 22 edges
4. `req()` - 17 edges
5. `NetworkScanner` - 16 edges
6. `JobExecutor` - 12 edges
7. `Job` - 8 edges
8. `WebSocketClient` - 8 edges
9. `Host` - 6 edges
10. `from_row()` - 5 edges

## Surprising Connections (you probably didn't know these)
- `main()` --calls--> `init_pool()`  [INFERRED]
  decebalus-backend/src/main.rs → decebalus-backend/src/db/mod.rs
- `list_cves()` --calls--> `list_cve_details()`  [INFERRED]
  decebalus-backend/src/api/cve.rs → decebalus-backend/src/db/repository.rs
- `handle_socket()` --calls--> `text`  [INFERRED]
  decebalus-backend/src/api/websocket.rs → decebalus-frontend/src/lib/pages/Attacks.svelte
- `refresh()` --calls--> `getJobs()`  [INFERRED]
  decebalus-frontend/src/lib/pages/Attacks.svelte → decebalus-frontend/src/lib/api.ts
- `refresh()` --calls--> `getHosts()`  [INFERRED]
  decebalus-frontend/src/lib/pages/Attacks.svelte → decebalus-frontend/src/lib/api.ts

## Communities (38 total, 13 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.1
Nodes (15): handle_socket(), ws_handler(), idx, jobId, rest, result, text, string (+7 more)

### Community 1 - "Community 1"
Cohesion: 0.09
Nodes (12): from_row(), get_cve_detail(), get_host(), get_job(), get_queued_jobs(), get_running_jobs(), get_scheduled_jobs_due(), get_unenriched_cve_ids() (+4 more)

### Community 2 - "Community 2"
Cohesion: 0.07
Nodes (13): FileSteal, IgnoreServerKey, FtpBruteForce, read_ftp_response(), try_ftp_login(), load_wordlist(), IgnoreServerKey, SshBruteForce (+5 more)

### Community 3 - "Community 3"
Cohesion: 0.11
Nodes (28): cancelJob(), createAttackJob(), createJob(), CveDetail, ExportFile, getConfig(), getCve(), getExports() (+20 more)

### Community 4 - "Community 4"
Cohesion: 0.12
Nodes (11): list_cves(), sync_cves(), init_pool(), list_cve_details(), JobExecutor, main(), shutdown_signal(), scenario_job_executor_runs_discovery_successfully() (+3 more)

### Community 5 - "Community 5"
Cohesion: 0.14
Nodes (4): NmapExtra, NmapScanResult, PortScanner, ServiceInfo

### Community 8 - "Community 8"
Cohesion: 0.19
Nodes (3): delete_host(), find_host_by_mac(), NetworkScanner

### Community 9 - "Community 9"
Cohesion: 0.26
Nodes (8): add_banner_adds_only_once(), add_port_adds_new_port(), add_port_sorts_ports(), add_port_updates_existing_port(), default_uses_correct_ip(), Host, host_new_initializes_correctly(), update_last_seen_changes_timestamp()

### Community 10 - "Community 10"
Cohesion: 0.21
Nodes (5): Job, new_initializes_correctly(), results_can_be_stored(), status_checks_work(), uuid_is_unique()

### Community 11 - "Community 11"
Cohesion: 0.32
Nodes (7): Config, test_default_config_is_empty(), test_get_missing_key_returns_none(), test_new_config_is_empty(), test_set_and_get_value(), test_set_overwrites_old_value(), test_setting_multiple_values()

### Community 12 - "Community 12"
Cohesion: 0.39
Nodes (7): cancel_job(), create_job(), get_job(), parse_job_from_request(), persist_job(), schedule_job(), validate_cidr()

### Community 13 - "Community 13"
Cohesion: 0.44
Nodes (5): default_matches_new(), DisplayStatus, new_initializes_correctly(), update_changes_status_and_timestamp(), update_multiple_times()

### Community 14 - "Community 14"
Cohesion: 0.22
Nodes (8): Clone the repository and install dependencies:, code:bash (node -v), code:bash (npm install), code:bash (npm run dev), code:bash (http://localhost:5173), Decebalus Dashboard, Prerequisites, Setup

### Community 15 - "Community 15"
Cohesion: 0.53
Nodes (4): Log, log_can_serialize_and_deserialize(), new_initializes_correctly(), optional_fields_can_be_none()

## Knowledge Gaps
- **33 isolated node(s):** `Repository`, `CreateJobRequest`, `CveDetail`, `JobPriority`, `Port` (+28 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **13 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What connects `Repository`, `CreateJobRequest`, `CveDetail` to the rest of the system?**
  _33 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.1 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.09 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.07 - nodes in this community are weakly interconnected._
- **Should `Community 3` be split into smaller, more focused modules?**
  _Cohesion score 0.11 - nodes in this community are weakly interconnected._
- **Should `Community 4` be split into smaller, more focused modules?**
  _Cohesion score 0.12 - nodes in this community are weakly interconnected._
- **Should `Community 5` be split into smaller, more focused modules?**
  _Cohesion score 0.14 - nodes in this community are weakly interconnected._