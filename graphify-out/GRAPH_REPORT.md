# Graph Report - Decebalus  (2026-07-29)

## Corpus Check
- 104 files · ~54,794 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 766 nodes · 1284 edges · 77 communities (49 shown, 28 thin omitted)
- Extraction: 79% EXTRACTED · 21% INFERRED · 0% AMBIGUOUS · INFERRED: 268 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `060decdb`
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
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
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
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 65|Community 65]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 67|Community 67]]
- [[_COMMUNITY_Community 68|Community 68]]
- [[_COMMUNITY_Community 69|Community 69]]

## God Nodes (most connected - your core abstractions)
1. `add_log()` - 31 edges
2. `req()` - 28 edges
3. `PortScanner` - 24 edges
4. `NetworkScanner` - 18 edges
5. `Decebalus` - 17 edges
6. `current()` - 17 edges
7. `main()` - 16 edges
8. `evaluate()` - 14 edges
9. `JobExecutor` - 13 edges
10. `list_hosts()` - 12 edges

## Surprising Connections (you probably didn't know these)
- `active_engagement_id()` --calls--> `get_active_engagement()`  [INFERRED]
  decebalus-backend/src/services/attacks/nxc_common.rs → decebalus-backend/src/db/repository.rs
- `create_engagement()` --calls--> `add_credential()`  [INFERRED]
  decebalus-backend/src/api/engagements.rs → decebalus-backend/src/db/repository.rs
- `active_engagement()` --calls--> `get_active_engagement()`  [INFERRED]
  decebalus-backend/src/api/engagements.rs → decebalus-backend/src/db/repository.rs
- `list_credentials()` --calls--> `get_active_engagement()`  [INFERRED]
  decebalus-backend/src/api/engagements.rs → decebalus-backend/src/db/repository.rs
- `active_engagement_id()` --calls--> `get_active_engagement()`  [INFERRED]
  decebalus-backend/src/api/findings.rs → decebalus-backend/src/db/repository.rs

## Communities (77 total, 28 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.06
Nodes (23): list_cves(), sync_cves(), freerdp_binary(), RdpBruteForce, try_rdp_login(), SmbBruteForce, smbclient_available(), try_smb_login() (+15 more)

### Community 1 - "Community 1"
Cohesion: 0.05
Nodes (25): list_modules(), FileSteal, IgnoreServerKey, FtpBruteForce, read_ftp_response(), try_ftp_login(), AdBloodhound, all_meta() (+17 more)

### Community 2 - "Community 2"
Cohesion: 0.07
Nodes (46): activateEngagement(), cancelJob(), createAttackJob(), createEngagement(), CreateEngagementBody, createJob(), Credential, CveDetail (+38 more)

### Community 3 - "Community 3"
Cohesion: 0.08
Nodes (21): handle_socket(), ws_handler(), idx, jobId, rest, result, text, scope_cidrs (+13 more)

### Community 4 - "Community 4"
Cohesion: 0.05
Nodes (41): 1. Master Rust in depth, 2. Understand offensive security tradecraft, 3. Build something genuinely useful and free, Architecture, Assumed-Breach Quickstart, Author, Basic Usage, code:block1 (src/) (+33 more)

### Community 5 - "Community 5"
Cohesion: 0.11
Nodes (27): get_config(), update_config(), init_pool(), cleanup_old_logs(), check_tools(), check_tools_covers_the_core_stack(), on_path(), print_report() (+19 more)

### Community 6 - "Community 6"
Cohesion: 0.11
Nodes (15): get_display_status(), update_display_status(), build_state(), DisplayDriver, DisplayService, DisplayState, make_driver(), attack_job_types_for() (+7 more)

### Community 7 - "Community 7"
Cohesion: 0.14
Nodes (15): AdRelayRecon, relay_targets_from_facts(), list_facts(), admin_cred_produces_headline_finding(), done_fact_for(), evaluate(), fact(), finding() (+7 more)

### Community 8 - "Community 8"
Cohesion: 0.2
Nodes (6): find_host_by_mac(), get_host(), host_from_row(), upsert_host(), upsert_host_tracked(), NetworkScanner

### Community 9 - "Community 9"
Cohesion: 0.11
Nodes (8): add_host_event(), delete_host(), from_row(), get_job(), get_queued_jobs(), get_running_jobs(), get_scheduled_jobs_due(), record_host_changes()

### Community 10 - "Community 10"
Cohesion: 0.24
Nodes (7): App, Finding, Host, main(), PortLite, ui(), if()

### Community 11 - "Community 11"
Cohesion: 0.18
Nodes (14): HistoryQuery, list_history(), get_config(), list_host_events(), set_engagement_status(), update_config(), change_detection_records_expected_events(), config_round_trips_through_key_value_store() (+6 more)

### Community 12 - "Community 12"
Cohesion: 0.26
Nodes (8): add_banner_adds_only_once(), add_port_adds_new_port(), add_port_sorts_ports(), add_port_updates_existing_port(), default_uses_correct_ip(), Host, host_new_initializes_correctly(), update_last_seen_changes_timestamp()

### Community 13 - "Community 13"
Cohesion: 0.25
Nodes (12): apply_schedule(), bad_request(), cancel_job(), create_job(), get_job(), is_blank(), is_valid_target(), parse_job_from_request() (+4 more)

### Community 14 - "Community 14"
Cohesion: 0.28
Nodes (7): get_cve_detail(), get_unenriched_cve_ids(), upsert_cve_detail(), CveEnrichment, nvd_api_key(), nvd_rate_ms(), parse_nvd_response_extracts_v3_score_desc_and_refs()

### Community 15 - "Community 15"
Cohesion: 0.21
Nodes (5): Job, new_initializes_correctly(), results_can_be_stored(), status_checks_work(), uuid_is_unique()

### Community 16 - "Community 16"
Cohesion: 0.32
Nodes (7): Config, test_default_config_is_empty(), test_get_missing_key_returns_none(), test_new_config_is_empty(), test_set_and_get_value(), test_set_overwrites_old_value(), test_setting_multiple_values()

### Community 17 - "Community 17"
Cohesion: 0.24
Nodes (9): activate_engagement(), active_engagement(), create_engagement(), CreateEngagementRequest, list_credentials(), engagement_from_row(), get_active_engagement(), get_engagement() (+1 more)

### Community 18 - "Community 18"
Cohesion: 0.25
Nodes (7): AdSmbEnum, os_from_line(), paren_value(), parse_smb_enum(), parses_signing_domain_and_os(), SmbHostInfo, creds_from_config()

### Community 19 - "Community 19"
Cohesion: 0.25
Nodes (7): AdAsrep, AdKerberoast, extracts_krb5tgs_hashes(), parse_hashes(), record_fact(), save_loot(), upsert_fact()

### Community 20 - "Community 20"
Cohesion: 0.24
Nodes (7): active_engagement_id(), binary_available(), Creds, nxc_binary(), NxcOutput, require_binary(), require_nxc()

### Community 21 - "Community 21"
Cohesion: 0.33
Nodes (7): AdSpray, collect_users(), lockout_threshold_fact(), parse_spray_hits(), parses_spray_hits_and_admin(), spray_is_safe(), get_facts_for_subject()

### Community 22 - "Community 22"
Cohesion: 0.28
Nodes (8): active_engagement_id(), dismiss_finding(), list_findings(), run_engine(), run_finding(), finding_from_row(), get_finding(), update_finding_status()

### Community 23 - "Community 23"
Cohesion: 0.33
Nodes (7): AdPasswordPolicy, int_after_colon(), none_threshold_means_no_lockout(), parse_pass_pol(), parses_lockout_policy(), PasswordPolicy, run_nxc()

### Community 24 - "Community 24"
Cohesion: 0.36
Nodes (7): AdNullSession, detects_null_session_and_shares(), null_session_allowed(), parse_shares(), parse_users(), parses_and_dedups_users(), ShareInfo

### Community 25 - "Community 25"
Cohesion: 0.25
Nodes (5): AdCredValidate, parse_auth(), record_credential(), add_credential(), emit()

### Community 26 - "Community 26"
Cohesion: 0.44
Nodes (5): default_matches_new(), DisplayStatus, new_initializes_correctly(), update_changes_status_and_timestamp(), update_multiple_times()

### Community 27 - "Community 27"
Cohesion: 0.22
Nodes (8): Clone the repository and install dependencies:, code:bash (node -v), code:bash (npm install), code:bash (npm run dev), code:bash (http://localhost:5173), Decebalus Dashboard, Prerequisites, Setup

### Community 28 - "Community 28"
Cohesion: 0.39
Nodes (5): esc(), render_html(), renders_self_contained_html_with_sections(), truncate(), vuln_severity()

### Community 29 - "Community 29"
Cohesion: 0.33
Nodes (4): AdBloodhound, parse_bh_zip(), record_finding(), upsert_finding()

### Community 30 - "Community 30"
Cohesion: 0.38
Nodes (5): AdAdcs, AdcsVuln, parse_adcs(), parses_esc_vulnerabilities(), run_tool()

### Community 31 - "Community 31"
Cohesion: 0.33
Nodes (5): Backend — working rules, Build / test, code:block1 (cd decebalus-backend && graphify update .), Consult the knowledge graph FIRST (token discipline), Keep the graph fresh

### Community 32 - "Community 32"
Cohesion: 0.6
Nodes (3): EpaperDisplay, init_pin(), init_pin_in()

### Community 33 - "Community 33"
Cohesion: 0.47
Nodes (4): enforces_ip_and_cidr_membership(), in_scope(), nets(), target_in_scope()

### Community 34 - "Community 34"
Cohesion: 0.33
Nodes (5): Build / check, code:block1 (cd decebalus-frontend && graphify update .), Consult the knowledge graph FIRST (token discipline), Frontend — working rules, Keep the graph fresh

### Community 35 - "Community 35"
Cohesion: 0.33
Nodes (5): Model, OPSEC guarantees, Rules (fact → next move), The Decebalus Assumed-Breach Playbook, The opening loop

### Community 36 - "Community 36"
Cohesion: 0.53
Nodes (4): Log, log_can_serialize_and_deserialize(), new_initializes_correctly(), optional_fields_can_be_none()

### Community 39 - "Community 39"
Cohesion: 0.8
Nodes (4): cve_lookup(), enrich_host(), get_host(), list_hosts()

## Knowledge Gaps
- **101 isolated node(s):** `Overview`, `Where Decebalus fits`, `1. Master Rust in depth`, `2. Understand offensive security tradecraft`, `3. Build something genuinely useful and free` (+96 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **28 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `parse_job_from_request()` connect `Community 13` to `Community 0`, `Community 1`?**
  _High betweenness centrality (0.151) - this node is a cross-community bridge._
- **Why does `string` connect `Community 13` to `Community 3`?**
  _High betweenness centrality (0.134) - this node is a cross-community bridge._
- **Why does `add_log()` connect `Community 0` to `Community 37`, `Community 7`, `Community 9`, `Community 14`, `Community 18`, `Community 19`, `Community 20`, `Community 21`, `Community 23`, `Community 24`, `Community 25`, `Community 29`, `Community 30`?**
  _High betweenness centrality (0.115) - this node is a cross-community bridge._
- **Are the 30 inferred relationships involving `add_log()` (e.g. with `.run()` and `.run()`) actually correct?**
  _`add_log()` has 30 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Overview`, `Where Decebalus fits`, `1. Master Rust in depth` to the rest of the system?**
  _101 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.06 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.05 - nodes in this community are weakly interconnected._