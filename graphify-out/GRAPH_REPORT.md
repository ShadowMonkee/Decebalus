# Graph Report - Decebalus  (2026-07-24)

## Corpus Check
- 63 files · ~31,537 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 384 nodes · 644 edges · 40 communities (28 shown, 12 thin omitted)
- Extraction: 82% EXTRACTED · 18% INFERRED · 0% AMBIGUOUS · INFERRED: 113 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `cc18c924`
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
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]

## God Nodes (most connected - your core abstractions)
1. `PortScanner` - 24 edges
2. `req()` - 18 edges
3. `add_log()` - 17 edges
4. `NetworkScanner` - 17 edges
5. `main()` - 14 edges
6. `JobExecutor` - 12 edges
7. `current()` - 10 edges
8. `Job` - 8 edges
9. `WebSocketClient` - 8 edges
10. `upsert_host()` - 7 edges

## Surprising Connections (you probably didn't know these)
- `update_config()` --calls--> `current()`  [INFERRED]
  decebalus-backend/src/api/config.rs → decebalus-backend/src/settings.rs
- `main()` --calls--> `cleanup_old_logs()`  [INFERRED]
  decebalus-backend/src/main.rs → decebalus-backend/src/db/repository.rs
- `main()` --calls--> `registry()`  [INFERRED]
  decebalus-backend/src/main.rs → decebalus-backend/src/services/attacks/mod.rs
- `main()` --calls--> `register_log_setter()`  [INFERRED]
  decebalus-backend/src/main.rs → decebalus-backend/src/settings.rs
- `main()` --calls--> `current()`  [INFERRED]
  decebalus-backend/src/main.rs → decebalus-backend/src/settings.rs

## Communities (40 total, 12 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.1
Nodes (15): handle_socket(), ws_handler(), idx, jobId, rest, result, text, string (+7 more)

### Community 1 - "Community 1"
Cohesion: 0.09
Nodes (17): delete_host(), find_host_by_mac(), from_row(), get_config(), get_cve_detail(), get_host(), get_job(), get_queued_jobs() (+9 more)

### Community 2 - "Community 2"
Cohesion: 0.13
Nodes (10): freerdp_binary(), RdpBruteForce, try_rdp_login(), SmbBruteForce, smbclient_available(), try_smb_login(), upsert_host(), NetworkScanner (+2 more)

### Community 3 - "Community 3"
Cohesion: 0.1
Nodes (30): cancelJob(), createAttackJob(), createJob(), CveDetail, ExportFile, getConfig(), getCve(), getExports() (+22 more)

### Community 4 - "Community 4"
Cohesion: 0.15
Nodes (5): add_log(), NmapExtra, NmapScanResult, PortScanner, ServiceInfo

### Community 5 - "Community 5"
Cohesion: 0.15
Nodes (20): get_config(), update_config(), init_pool(), cleanup_old_logs(), main(), shutdown_signal(), default_fallback_ports(), get_bool() (+12 more)

### Community 6 - "Community 6"
Cohesion: 0.13
Nodes (9): FileSteal, IgnoreServerKey, FtpBruteForce, read_ftp_response(), try_ftp_login(), load_wordlist(), IgnoreServerKey, SshBruteForce (+1 more)

### Community 7 - "Community 7"
Cohesion: 0.22
Nodes (5): JobExecutor, scenario_job_executor_runs_discovery_successfully(), scenario_resume_incomplete_jobs_requeues_and_runs(), scenario_run_queue_spawns_jobs(), test_state()

### Community 8 - "Community 8"
Cohesion: 0.26
Nodes (8): add_banner_adds_only_once(), add_port_adds_new_port(), add_port_sorts_ports(), add_port_updates_existing_port(), default_uses_correct_ip(), Host, host_new_initializes_correctly(), update_last_seen_changes_timestamp()

### Community 9 - "Community 9"
Cohesion: 0.21
Nodes (5): Job, new_initializes_correctly(), results_can_be_stored(), status_checks_work(), uuid_is_unique()

### Community 10 - "Community 10"
Cohesion: 0.17
Nodes (4): WebSocketClient, WebSocketOptions, connectionStatus, wsMessages

### Community 11 - "Community 11"
Cohesion: 0.32
Nodes (7): Config, test_default_config_is_empty(), test_get_missing_key_returns_none(), test_new_config_is_empty(), test_set_and_get_value(), test_set_overwrites_old_value(), test_setting_multiple_values()

### Community 12 - "Community 12"
Cohesion: 0.24
Nodes (7): list_modules(), all_meta(), AttackModule, FileSteal, module_for(), ModuleMeta, registry()

### Community 13 - "Community 13"
Cohesion: 0.36
Nodes (8): apply_schedule(), cancel_job(), create_job(), get_job(), parse_job_from_request(), persist_job(), schedule_job(), validate_cidr()

### Community 14 - "Community 14"
Cohesion: 0.29
Nodes (7): list_cves(), sync_cves(), cve_lookup(), enrich_host(), get_host(), list_hosts(), list_cve_details()

### Community 15 - "Community 15"
Cohesion: 0.44
Nodes (5): default_matches_new(), DisplayStatus, new_initializes_correctly(), update_changes_status_and_timestamp(), update_multiple_times()

### Community 16 - "Community 16"
Cohesion: 0.22
Nodes (8): Clone the repository and install dependencies:, code:bash (node -v), code:bash (npm install), code:bash (npm run dev), code:bash (http://localhost:5173), Decebalus Dashboard, Prerequisites, Setup

### Community 17 - "Community 17"
Cohesion: 0.53
Nodes (4): Log, log_can_serialize_and_deserialize(), new_initializes_correctly(), optional_fields_can_be_none()

## Knowledge Gaps
- **35 isolated node(s):** `ModuleMeta`, `AttackModule`, `ServiceInfo`, `NmapScanResult`, `NmapExtra` (+30 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **12 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `current()` connect `Community 2` to `Community 1`, `Community 4`, `Community 5`, `Community 7`?**
  _High betweenness centrality (0.047) - this node is a cross-community bridge._
- **Why does `main()` connect `Community 5` to `Community 1`, `Community 2`, `Community 12`, `Community 7`?**
  _High betweenness centrality (0.040) - this node is a cross-community bridge._
- **Why does `add_log()` connect `Community 4` to `Community 1`, `Community 2`, `Community 7`?**
  _High betweenness centrality (0.035) - this node is a cross-community bridge._
- **Are the 16 inferred relationships involving `add_log()` (e.g. with `.run()` and `.run()`) actually correct?**
  _`add_log()` has 16 INFERRED edges - model-reasoned connections that need verification._
- **Are the 12 inferred relationships involving `main()` (e.g. with `.new()` and `registry()`) actually correct?**
  _`main()` has 12 INFERRED edges - model-reasoned connections that need verification._
- **What connects `ModuleMeta`, `AttackModule`, `ServiceInfo` to the rest of the system?**
  _35 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.1 - nodes in this community are weakly interconnected._