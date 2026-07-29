# Graph Report - decebalus-backend  (2026-07-29)

## Corpus Check
- 80 files · ~39,269 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 589 nodes · 981 edges · 70 communities (39 shown, 31 thin omitted)
- Extraction: 80% EXTRACTED · 20% INFERRED · 0% AMBIGUOUS · INFERRED: 198 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `cc18c924`
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
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 63|Community 63]]
- [[_COMMUNITY_Community 64|Community 64]]

## God Nodes (most connected - your core abstractions)
1. `add_log()` - 31 edges
2. `PortScanner` - 24 edges
3. `NetworkScanner` - 18 edges
4. `current()` - 17 edges
5. `evaluate()` - 14 edges
6. `main()` - 13 edges
7. `JobExecutor` - 13 edges
8. `upsert_host_tracked()` - 12 edges
9. `require_nxc()` - 12 edges
10. `App` - 11 edges

## Surprising Connections (you probably didn't know these)
- `rule_engine_persists_ranked_findings_from_facts()` --calls--> `upsert_fact()`  [INFERRED]
  tests/rule_engine_tests.rs → src/db/repository.rs
- `engagement_create_get_and_active_selection()` --calls--> `get_engagement()`  [INFERRED]
  tests/repository_tests.rs → src/db/repository.rs
- `engagement_create_get_and_active_selection()` --calls--> `get_active_engagement()`  [INFERRED]
  tests/repository_tests.rs → src/db/repository.rs
- `engagement_create_get_and_active_selection()` --calls--> `set_engagement_status()`  [INFERRED]
  tests/repository_tests.rs → src/db/repository.rs
- `credential_upsert_upgrades_validation()` --calls--> `add_credential()`  [INFERRED]
  tests/repository_tests.rs → src/db/repository.rs

## Communities (70 total, 31 thin omitted)

### Community 0 - "NetExec AD Helpers"
Cohesion: 0.08
Nodes (21): HistoryQuery, list_history(), delete_host(), find_host_by_mac(), list_host_events(), set_engagement_status(), upsert_host_tracked(), build_state() (+13 more)

### Community 1 - "CVE Enrichment & Repository"
Cohesion: 0.08
Nodes (22): list_modules(), FtpBruteForce, read_ftp_response(), try_ftp_login(), AdBloodhound, all_meta(), AttackModule, load_wordlist() (+14 more)

### Community 2 - "Engagement Tests & Spray"
Cohesion: 0.13
Nodes (6): NmapExtra, NmapScanResult, parse_nmap_xml_extracts_ports_services_host_and_mac(), parse_vulners_output_extracts_cves(), PortScanner, ServiceInfo

### Community 3 - "Attack Module Registry"
Cohesion: 0.14
Nodes (22): get_config(), update_config(), init_pool(), cleanup_old_logs(), main(), shutdown_signal(), default_fallback_ports(), from_stored_falls_back_to_defaults_when_absent() (+14 more)

### Community 4 - "Network Scanner (Discovery)"
Cohesion: 0.09
Nodes (10): add_host_event(), from_row(), get_host(), get_job(), get_queued_jobs(), get_running_jobs(), get_scheduled_jobs_due(), host_from_row() (+2 more)

### Community 5 - "Port Scanner (Nmap)"
Cohesion: 0.12
Nodes (12): update_display(), update_display_status(), upsert_host(), attack_job_types_for(), meta(), Orchestrator, current(), AppState (+4 more)

### Community 6 - "Runtime Settings"
Cohesion: 0.17
Nodes (9): list_cves(), sync_cves(), add_log(), list_cve_details(), JobExecutor, scenario_job_executor_runs_discovery_successfully(), scenario_resume_incomplete_jobs_requeues_and_runs(), scenario_run_queue_spawns_jobs() (+1 more)

### Community 7 - "Autonomous Orchestrator"
Cohesion: 0.26
Nodes (6): App, Finding, Host, main(), PortLite, ui()

### Community 8 - "Rule Engine"
Cohesion: 0.24
Nodes (12): admin_cred_produces_headline_finding(), done_fact_for(), evaluate(), fact(), finding(), host_open(), priv_rank(), signing_disabled_yields_auto_relay_recon() (+4 more)

### Community 9 - "Job Executor"
Cohesion: 0.16
Nodes (9): AdAsrep, AdKerberoast, extracts_krb5tgs_hashes(), parse_hashes(), AdRelayRecon, relay_targets_from_facts(), record_finding(), save_loot() (+1 more)

### Community 10 - "Terminal TUI"
Cohesion: 0.26
Nodes (8): add_banner_adds_only_once(), add_port_adds_new_port(), add_port_sorts_ports(), add_port_updates_existing_port(), default_uses_correct_ip(), Host, host_new_initializes_correctly(), update_last_seen_changes_timestamp()

### Community 11 - "Host Model"
Cohesion: 0.21
Nodes (5): Job, new_initializes_correctly(), results_can_be_stored(), status_checks_work(), uuid_is_unique()

### Community 12 - "Job Model"
Cohesion: 0.28
Nodes (7): get_cve_detail(), get_unenriched_cve_ids(), upsert_cve_detail(), CveEnrichment, nvd_api_key(), nvd_rate_ms(), parse_nvd_response_extracts_v3_score_desc_and_refs()

### Community 13 - "Jobs API"
Cohesion: 0.19
Nodes (10): activate_engagement(), active_engagement(), create_engagement(), CreateEngagementRequest, list_credentials(), engagement_from_row(), get_active_engagement(), get_engagement() (+2 more)

### Community 14 - "Config Model"
Cohesion: 0.28
Nodes (11): apply_schedule(), bad_request(), cancel_job(), create_job(), get_job(), is_blank(), is_valid_target(), parse_job_from_request() (+3 more)

### Community 15 - "Display Status Model"
Cohesion: 0.32
Nodes (7): Config, test_default_config_is_empty(), test_get_missing_key_returns_none(), test_new_config_is_empty(), test_set_and_get_value(), test_set_overwrites_old_value(), test_setting_multiple_values()

### Community 16 - "HTML Report"
Cohesion: 0.33
Nodes (7): AdSpray, collect_users(), lockout_threshold_fact(), parse_spray_hits(), parses_spray_hits_and_admin(), spray_is_safe(), get_facts_for_subject()

### Community 17 - "Dependency Doctor"
Cohesion: 0.29
Nodes (6): AdSmbEnum, os_from_line(), paren_value(), parse_smb_enum(), parses_signing_domain_and_os(), SmbHostInfo

### Community 18 - "Log Model"
Cohesion: 0.24
Nodes (7): active_engagement_id(), binary_available(), Creds, nxc_binary(), NxcOutput, require_binary(), require_nxc()

### Community 19 - "Scope Lock"
Cohesion: 0.44
Nodes (5): default_matches_new(), DisplayStatus, new_initializes_correctly(), update_changes_status_and_timestamp(), update_multiple_times()

### Community 20 - "E-paper Display"
Cohesion: 0.28
Nodes (8): active_engagement_id(), dismiss_finding(), list_findings(), run_engine(), run_finding(), finding_from_row(), get_finding(), update_finding_status()

### Community 21 - "Password Policy Parser"
Cohesion: 0.33
Nodes (7): AdPasswordPolicy, int_after_colon(), none_threshold_means_no_lockout(), parse_pass_pol(), parses_lockout_policy(), PasswordPolicy, creds_from_config()

### Community 22 - "SFTP File Steal"
Cohesion: 0.25
Nodes (5): AdCredValidate, parse_auth(), record_credential(), add_credential(), emit()

### Community 23 - "Hosts API"
Cohesion: 0.36
Nodes (7): AdNullSession, detects_null_session_and_shares(), null_session_allowed(), parse_shares(), parse_users(), parses_and_dedups_users(), ShareInfo

### Community 24 - "Mock Display"
Cohesion: 0.39
Nodes (5): esc(), render_html(), renders_self_contained_html_with_sections(), truncate(), vuln_severity()

### Community 25 - "Exports API"
Cohesion: 0.33
Nodes (4): AdShareHunt, is_interesting_share(), record_fact(), upsert_fact()

### Community 26 - "Fact Model"
Cohesion: 0.33
Nodes (4): AdBloodhound, parse_bh_zip(), run_nxc(), run_tool()

### Community 27 - "Finding Model"
Cohesion: 0.53
Nodes (4): Log, log_can_serialize_and_deserialize(), new_initializes_correctly(), optional_fields_can_be_none()

### Community 28 - "Engagement Model"
Cohesion: 0.53
Nodes (5): check_tools(), check_tools_covers_the_core_stack(), on_path(), print_report(), ToolStatus

### Community 29 - "Host Status Enum"
Cohesion: 0.47
Nodes (4): enforces_ip_and_cidr_membership(), in_scope(), nets(), target_in_scope()

### Community 30 - "Create Job Request"
Cohesion: 0.6
Nodes (3): EpaperDisplay, init_pin(), init_pin_in()

### Community 31 - "WebSocket Handler"
Cohesion: 0.47
Nodes (4): AdAdcs, AdcsVuln, parse_adcs(), parses_esc_vulnerabilities()

### Community 33 - "FTP Brute Module"
Cohesion: 0.33
Nodes (5): Backend — working rules, Build / test, code:block1 (cd decebalus-backend && graphify update .), Consult the knowledge graph FIRST (token discipline), Keep the graph fresh

### Community 34 - "SMB Brute Module"
Cohesion: 0.8
Nodes (4): cve_lookup(), enrich_host(), get_host(), list_hosts()

## Knowledge Gaps
- **27 isolated node(s):** `ToolStatus`, `Finding`, `PortLite`, `Host`, `CveDetail` (+22 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **31 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `add_log()` connect `Runtime Settings` to `CVE Enrichment & Repository`, `Engagement Tests & Spray`, `Network Scanner (Discovery)`, `Job Executor`, `Job Model`, `HTML Report`, `Dependency Doctor`, `Log Model`, `Password Policy Parser`, `SFTP File Steal`, `Hosts API`, `Exports API`, `Fact Model`, `WebSocket Handler`?**
  _High betweenness centrality (0.190) - this node is a cross-community bridge._
- **Why does `current()` connect `Port Scanner (Nmap)` to `NetExec AD Helpers`, `Engagement Tests & Spray`, `Attack Module Registry`, `Runtime Settings`, `Job Model`, `HTML Report`, `Fact Model`?**
  _High betweenness centrality (0.140) - this node is a cross-community bridge._
- **Why does `main()` connect `Attack Module Registry` to `CVE Enrichment & Repository`, `Port Scanner (Nmap)`, `Runtime Settings`, `Autonomous Orchestrator`, `Engagement Model`?**
  _High betweenness centrality (0.078) - this node is a cross-community bridge._
- **Are the 30 inferred relationships involving `add_log()` (e.g. with `.execute_job()` and `.run_port_scan()`) actually correct?**
  _`add_log()` has 30 INFERRED edges - model-reasoned connections that need verification._
- **Are the 16 inferred relationships involving `current()` (e.g. with `.new()` and `main()`) actually correct?**
  _`current()` has 16 INFERRED edges - model-reasoned connections that need verification._
- **What connects `ToolStatus`, `Finding`, `PortLite` to the rest of the system?**
  _27 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `NetExec AD Helpers` be split into smaller, more focused modules?**
  _Cohesion score 0.08 - nodes in this community are weakly interconnected._