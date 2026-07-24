# Graph Report - .  (2026-05-25)

## Corpus Check
- Corpus is ~15,580 words - fits in a single context window. You may not need a graph.

## Summary
- 265 nodes · 354 edges · 35 communities (17 shown, 18 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 19 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_DB Repository Query Layer|DB Repository Query Layer]]
- [[_COMMUNITY_CVE Sync & Job Execution|CVE Sync & Job Execution]]
- [[_COMMUNITY_Nmap Port Scanner|Nmap Port Scanner]]
- [[_COMMUNITY_In-Memory Repository|In-Memory Repository]]
- [[_COMMUNITY_Postgres DB Repository|Postgres DB Repository]]
- [[_COMMUNITY_Host Model & Tests|Host Model & Tests]]
- [[_COMMUNITY_Job Model & States|Job Model & States]]
- [[_COMMUNITY_Config Model & Tests|Config Model & Tests]]
- [[_COMMUNITY_Network Host Scanner|Network Host Scanner]]
- [[_COMMUNITY_Display Status Model|Display Status Model]]
- [[_COMMUNITY_Jobs REST API|Jobs REST API]]
- [[_COMMUNITY_Log Model|Log Model]]
- [[_COMMUNITY_Exports API|Exports API]]
- [[_COMMUNITY_Application State|Application State]]
- [[_COMMUNITY_Host Status Model|Host Status Model]]
- [[_COMMUNITY_Job Request Model|Job Request Model]]
- [[_COMMUNITY_Config REST API|Config REST API]]
- [[_COMMUNITY_WebSocket Handler|WebSocket Handler]]
- [[_COMMUNITY_SSH Brute Force|SSH Brute Force]]
- [[_COMMUNITY_FTP Brute Force|FTP Brute Force]]
- [[_COMMUNITY_SSH File Exfiltration|SSH File Exfiltration]]
- [[_COMMUNITY_CVE Detail Model|CVE Detail Model]]
- [[_COMMUNITY_Port Model|Port Model]]
- [[_COMMUNITY_Service Model|Service Model]]
- [[_COMMUNITY_Job Priority Model|Job Priority Model]]
- [[_COMMUNITY_Vulnerability Model|Vulnerability Model]]
- [[_COMMUNITY_Repository Trait|Repository Trait]]

## God Nodes (most connected - your core abstractions)
1. `PortScanner` - 24 edges
2. `InMemoryRepository` - 22 edges
3. `DbRepository` - 22 edges
4. `JobExecutor` - 12 edges
5. `NetworkScanner` - 11 edges
6. `Job` - 8 edges
7. `Host` - 6 edges
8. `main()` - 5 edges
9. `Config` - 5 edges
10. `from_row()` - 5 edges

## Surprising Connections (you probably didn't know these)
- `main()` --calls--> `init_pool()`  [INFERRED]
  src/main.rs → src/db/mod.rs
- `list_cves()` --calls--> `list_cve_details()`  [INFERRED]
  src/api/cve.rs → src/db/repository.rs

## Communities (35 total, 18 thin omitted)

### Community 0 - "DB Repository Query Layer"
Cohesion: 0.09
Nodes (12): from_row(), get_cve_detail(), get_host(), get_job(), get_queued_jobs(), get_running_jobs(), get_scheduled_jobs_due(), get_unenriched_cve_ids() (+4 more)

### Community 1 - "CVE Sync & Job Execution"
Cohesion: 0.12
Nodes (11): list_cves(), sync_cves(), init_pool(), list_cve_details(), JobExecutor, main(), shutdown_signal(), scenario_job_executor_runs_discovery_successfully() (+3 more)

### Community 2 - "Nmap Port Scanner"
Cohesion: 0.14
Nodes (4): NmapExtra, NmapScanResult, PortScanner, ServiceInfo

### Community 5 - "Host Model & Tests"
Cohesion: 0.26
Nodes (8): add_banner_adds_only_once(), add_port_adds_new_port(), add_port_sorts_ports(), add_port_updates_existing_port(), default_uses_correct_ip(), Host, host_new_initializes_correctly(), update_last_seen_changes_timestamp()

### Community 6 - "Job Model & States"
Cohesion: 0.21
Nodes (5): Job, new_initializes_correctly(), results_can_be_stored(), status_checks_work(), uuid_is_unique()

### Community 7 - "Config Model & Tests"
Cohesion: 0.32
Nodes (7): Config, test_default_config_is_empty(), test_get_missing_key_returns_none(), test_new_config_is_empty(), test_set_and_get_value(), test_set_overwrites_old_value(), test_setting_multiple_values()

### Community 9 - "Display Status Model"
Cohesion: 0.44
Nodes (5): default_matches_new(), DisplayStatus, new_initializes_correctly(), update_changes_status_and_timestamp(), update_multiple_times()

### Community 10 - "Jobs REST API"
Cohesion: 0.39
Nodes (7): cancel_job(), create_job(), get_job(), parse_job_from_request(), persist_job(), schedule_job(), validate_cidr()

### Community 11 - "Log Model"
Cohesion: 0.53
Nodes (4): Log, log_can_serialize_and_deserialize(), new_initializes_correctly(), optional_fields_can_be_none()

## Knowledge Gaps
- **10 isolated node(s):** `CveDetail`, `Port`, `Service`, `JobPriority`, `Vulnerability` (+5 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **18 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `list_cve_details()` connect `CVE Sync & Job Execution` to `DB Repository Query Layer`?**
  _High betweenness centrality (0.038) - this node is a cross-community bridge._
- **What connects `CveDetail`, `Port`, `Service` to the rest of the system?**
  _10 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `DB Repository Query Layer` be split into smaller, more focused modules?**
  _Cohesion score 0.09 - nodes in this community are weakly interconnected._
- **Should `CVE Sync & Job Execution` be split into smaller, more focused modules?**
  _Cohesion score 0.12 - nodes in this community are weakly interconnected._
- **Should `Nmap Port Scanner` be split into smaller, more focused modules?**
  _Cohesion score 0.14 - nodes in this community are weakly interconnected._
- **Should `In-Memory Repository` be split into smaller, more focused modules?**
  _Cohesion score 0.09 - nodes in this community are weakly interconnected._
- **Should `Postgres DB Repository` be split into smaller, more focused modules?**
  _Cohesion score 0.09 - nodes in this community are weakly interconnected._