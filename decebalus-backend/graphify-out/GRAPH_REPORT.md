# Graph Report - decebalus-backend  (2026-07-29)

## Corpus Check
- 84 files · ~41,043 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 618 nodes · 1037 edges · 59 communities (30 shown, 29 thin omitted)
- Extraction: 80% EXTRACTED · 20% INFERRED · 0% AMBIGUOUS · INFERRED: 209 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `060decdb`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_NetExec AD Helpers|NetExec AD Helpers]]
- [[_COMMUNITY_CVE Enrichment & Repository|CVE Enrichment & Repository]]
- [[_COMMUNITY_Engagement Tests & Spray|Engagement Tests & Spray]]
- [[_COMMUNITY_Attack Module Registry|Attack Module Registry]]
- [[_COMMUNITY_Network Scanner (Discovery)|Network Scanner (Discovery)]]
- [[_COMMUNITY_Port Scanner (Nmap)|Port Scanner (Nmap)]]
- [[_COMMUNITY_Runtime Settings|Runtime Settings]]
- [[_COMMUNITY_Autonomous Orchestrator|Autonomous Orchestrator]]
- [[_COMMUNITY_Rule Engine|Rule Engine]]
- [[_COMMUNITY_Job Executor|Job Executor]]
- [[_COMMUNITY_Terminal TUI|Terminal TUI]]
- [[_COMMUNITY_Host Model|Host Model]]
- [[_COMMUNITY_Job Model|Job Model]]
- [[_COMMUNITY_Jobs API|Jobs API]]
- [[_COMMUNITY_Config Model|Config Model]]
- [[_COMMUNITY_Display Status Model|Display Status Model]]
- [[_COMMUNITY_HTML Report|HTML Report]]
- [[_COMMUNITY_Dependency Doctor|Dependency Doctor]]
- [[_COMMUNITY_Log Model|Log Model]]
- [[_COMMUNITY_Scope Lock|Scope Lock]]
- [[_COMMUNITY_E-paper Display|E-paper Display]]
- [[_COMMUNITY_Password Policy Parser|Password Policy Parser]]
- [[_COMMUNITY_SFTP File Steal|SFTP File Steal]]
- [[_COMMUNITY_Hosts API|Hosts API]]
- [[_COMMUNITY_Mock Display|Mock Display]]
- [[_COMMUNITY_Exports API|Exports API]]
- [[_COMMUNITY_Fact Model|Fact Model]]
- [[_COMMUNITY_Finding Model|Finding Model]]
- [[_COMMUNITY_Engagement Model|Engagement Model]]
- [[_COMMUNITY_Host Status Enum|Host Status Enum]]
- [[_COMMUNITY_Create Job Request|Create Job Request]]
- [[_COMMUNITY_WebSocket Handler|WebSocket Handler]]
- [[_COMMUNITY_SSH Brute Module|SSH Brute Module]]
- [[_COMMUNITY_FTP Brute Module|FTP Brute Module]]
- [[_COMMUNITY_SMB Brute Module|SMB Brute Module]]
- [[_COMMUNITY_RDP Brute Module|RDP Brute Module]]
- [[_COMMUNITY_File Steal Module|File Steal Module]]
- [[_COMMUNITY_AD SMB Enum Module|AD SMB Enum Module]]
- [[_COMMUNITY_AD Null Session Module|AD Null Session Module]]
- [[_COMMUNITY_AD Password Policy Module|AD Password Policy Module]]
- [[_COMMUNITY_AD Share Hunt Module|AD Share Hunt Module]]
- [[_COMMUNITY_AD Cred Validate Module|AD Cred Validate Module]]
- [[_COMMUNITY_AD Spray Module|AD Spray Module]]
- [[_COMMUNITY_AD Kerberoast Module|AD Kerberoast Module]]
- [[_COMMUNITY_AD AS-REP Module|AD AS-REP Module]]
- [[_COMMUNITY_AD ADCS Module|AD ADCS Module]]
- [[_COMMUNITY_AD Relay Recon Module|AD Relay Recon Module]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]

## God Nodes (most connected - your core abstractions)
1. `add_log()` - 31 edges
2. `PortScanner` - 24 edges
3. `NetworkScanner` - 18 edges
4. `current()` - 17 edges
5. `main()` - 16 edges
6. `evaluate()` - 14 edges
7. `JobExecutor` - 13 edges
8. `upsert_host_tracked()` - 12 edges
9. `require_nxc()` - 12 edges
10. `App` - 11 edges

## Surprising Connections (you probably didn't know these)
- `rule_engine_persists_ranked_findings_from_facts()` --calls--> `upsert_fact()`  [INFERRED]
  tests/rule_engine_tests.rs → src/db/repository.rs
- `change_detection_records_expected_events()` --calls--> `upsert_host_tracked()`  [INFERRED]
  tests/repository_tests.rs → src/db/repository.rs
- `re_upserting_unchanged_host_produces_no_duplicate_events()` --calls--> `upsert_host_tracked()`  [INFERRED]
  tests/repository_tests.rs → src/db/repository.rs
- `engagement_create_get_and_active_selection()` --calls--> `set_engagement_status()`  [INFERRED]
  tests/repository_tests.rs → src/db/repository.rs
- `credential_upsert_upgrades_validation()` --calls--> `add_credential()`  [INFERRED]
  tests/repository_tests.rs → src/db/repository.rs

## Communities (59 total, 29 thin omitted)

### Community 0 - "NetExec AD Helpers"
Cohesion: 0.05
Nodes (48): AdAdcs, AdcsVuln, parse_adcs(), parses_esc_vulnerabilities(), AdAsrep, AdBloodhound, parse_bh_zip(), AdCredValidate (+40 more)

### Community 1 - "CVE Enrichment & Repository"
Cohesion: 0.05
Nodes (41): activate_engagement(), active_engagement(), create_engagement(), CreateEngagementRequest, list_credentials(), active_engagement_id(), dismiss_finding(), list_findings() (+33 more)

### Community 2 - "Engagement Tests & Spray"
Cohesion: 0.1
Nodes (29): get_config(), update_config(), init_pool(), cleanup_old_logs(), check_tools(), check_tools_covers_the_core_stack(), on_path(), print_report() (+21 more)

### Community 3 - "Attack Module Registry"
Cohesion: 0.08
Nodes (22): list_modules(), FtpBruteForce, read_ftp_response(), try_ftp_login(), AdBloodhound, all_meta(), AttackModule, load_wordlist() (+14 more)

### Community 4 - "Network Scanner (Discovery)"
Cohesion: 0.12
Nodes (9): delete_host(), find_host_by_mac(), upsert_host_tracked(), build_state(), DisplayDriver, DisplayService, DisplayState, make_driver() (+1 more)

### Community 5 - "Port Scanner (Nmap)"
Cohesion: 0.13
Nodes (6): NmapExtra, NmapScanResult, parse_nmap_xml_extracts_ports_services_host_and_mac(), parse_vulners_output_extracts_cves(), PortScanner, ServiceInfo

### Community 6 - "Runtime Settings"
Cohesion: 0.12
Nodes (20): record_credential(), add_credential(), credential_from_row(), cipher_for(), CryptoError, current(), decrypt(), decrypt_str() (+12 more)

### Community 7 - "Autonomous Orchestrator"
Cohesion: 0.12
Nodes (12): update_display(), update_display_status(), upsert_host(), attack_job_types_for(), meta(), Orchestrator, current(), AppState (+4 more)

### Community 8 - "Rule Engine"
Cohesion: 0.14
Nodes (15): AdRelayRecon, relay_targets_from_facts(), list_facts(), admin_cred_produces_headline_finding(), done_fact_for(), evaluate(), fact(), finding() (+7 more)

### Community 9 - "Job Executor"
Cohesion: 0.17
Nodes (9): list_cves(), sync_cves(), add_log(), list_cve_details(), JobExecutor, scenario_job_executor_runs_discovery_successfully(), scenario_resume_incomplete_jobs_requeues_and_runs(), scenario_run_queue_spawns_jobs() (+1 more)

### Community 10 - "Terminal TUI"
Cohesion: 0.18
Nodes (9): download_export(), export_dir(), list_exports(), App, Finding, Host, main(), PortLite (+1 more)

### Community 11 - "Host Model"
Cohesion: 0.26
Nodes (8): add_banner_adds_only_once(), add_port_adds_new_port(), add_port_sorts_ports(), add_port_updates_existing_port(), default_uses_correct_ip(), Host, host_new_initializes_correctly(), update_last_seen_changes_timestamp()

### Community 12 - "Job Model"
Cohesion: 0.21
Nodes (5): Job, new_initializes_correctly(), results_can_be_stored(), status_checks_work(), uuid_is_unique()

### Community 13 - "Jobs API"
Cohesion: 0.28
Nodes (11): apply_schedule(), bad_request(), cancel_job(), create_job(), get_job(), is_blank(), is_valid_target(), parse_job_from_request() (+3 more)

### Community 14 - "Config Model"
Cohesion: 0.28
Nodes (7): get_cve_detail(), get_unenriched_cve_ids(), upsert_cve_detail(), CveEnrichment, nvd_api_key(), nvd_rate_ms(), parse_nvd_response_extracts_v3_score_desc_and_refs()

### Community 15 - "Display Status Model"
Cohesion: 0.32
Nodes (7): Config, test_default_config_is_empty(), test_get_missing_key_returns_none(), test_new_config_is_empty(), test_set_and_get_value(), test_set_overwrites_old_value(), test_setting_multiple_values()

### Community 16 - "HTML Report"
Cohesion: 0.33
Nodes (7): AdSpray, collect_users(), lockout_threshold_fact(), parse_spray_hits(), parses_spray_hits_and_admin(), spray_is_safe(), get_facts_for_subject()

### Community 17 - "Dependency Doctor"
Cohesion: 0.44
Nodes (5): default_matches_new(), DisplayStatus, new_initializes_correctly(), update_changes_status_and_timestamp(), update_multiple_times()

### Community 18 - "Log Model"
Cohesion: 0.39
Nodes (5): esc(), render_html(), renders_self_contained_html_with_sections(), truncate(), vuln_severity()

### Community 19 - "Scope Lock"
Cohesion: 0.53
Nodes (4): Log, log_can_serialize_and_deserialize(), new_initializes_correctly(), optional_fields_can_be_none()

### Community 20 - "E-paper Display"
Cohesion: 0.47
Nodes (4): enforces_ip_and_cidr_membership(), in_scope(), nets(), target_in_scope()

### Community 21 - "Password Policy Parser"
Cohesion: 0.6
Nodes (3): EpaperDisplay, init_pin(), init_pin_in()

### Community 22 - "SFTP File Steal"
Cohesion: 0.33
Nodes (5): Backend — working rules, Build / test, code:block1 (cd decebalus-backend && graphify update .), Consult the knowledge graph FIRST (token discipline), Keep the graph fresh

### Community 23 - "Hosts API"
Cohesion: 0.8
Nodes (4): cve_lookup(), enrich_host(), get_host(), list_hosts()

## Knowledge Gaps
- **28 isolated node(s):** `ToolStatus`, `Assets`, `Finding`, `PortLite`, `Host` (+23 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **29 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `add_log()` connect `Job Executor` to `NetExec AD Helpers`, `CVE Enrichment & Repository`, `Attack Module Registry`, `Port Scanner (Nmap)`, `Rule Engine`, `Config Model`, `HTML Report`?**
  _High betweenness centrality (0.190) - this node is a cross-community bridge._
- **Why does `current()` connect `Autonomous Orchestrator` to `NetExec AD Helpers`, `Engagement Tests & Spray`, `Network Scanner (Discovery)`, `Port Scanner (Nmap)`, `Job Executor`, `Config Model`, `HTML Report`?**
  _High betweenness centrality (0.140) - this node is a cross-community bridge._
- **Why does `main()` connect `Engagement Tests & Spray` to `Attack Module Registry`, `Runtime Settings`, `Autonomous Orchestrator`, `Job Executor`, `Terminal TUI`?**
  _High betweenness centrality (0.101) - this node is a cross-community bridge._
- **Are the 30 inferred relationships involving `add_log()` (e.g. with `.execute_job()` and `.run_port_scan()`) actually correct?**
  _`add_log()` has 30 INFERRED edges - model-reasoned connections that need verification._
- **Are the 16 inferred relationships involving `current()` (e.g. with `.new()` and `main()`) actually correct?**
  _`current()` has 16 INFERRED edges - model-reasoned connections that need verification._
- **Are the 13 inferred relationships involving `main()` (e.g. with `print_report()` and `decrypt()`) actually correct?**
  _`main()` has 13 INFERRED edges - model-reasoned connections that need verification._
- **What connects `ToolStatus`, `Assets`, `Finding` to the rest of the system?**
  _28 weakly-connected nodes found - possible documentation gaps or missing edges._