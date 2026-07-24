# Graph Report - .  (2026-05-25)

## Corpus Check
- Corpus is ~7,522 words - fits in a single context window. You may not need a graph.

## Summary
- 121 nodes · 171 edges · 20 communities (12 shown, 8 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 4 edges (avg confidence: 0.85)
- Token cost: 55,500 input · 11,342 output

## Community Hubs (Navigation)
- [[_COMMUNITY_API Function Layer|API Function Layer]]
- [[_COMMUNITY_Page Logic & Control Flow|Page Logic & Control Flow]]
- [[_COMMUNITY_WebSocket Client Layer|WebSocket Client Layer]]
- [[_COMMUNITY_API Read Operations|API Read Operations]]
- [[_COMMUNITY_App Shell & Routing|App Shell & Routing]]
- [[_COMMUNITY_Dashboard & Export Views|Dashboard & Export Views]]
- [[_COMMUNITY_Job Lifecycle & Recon|Job Lifecycle & Recon]]
- [[_COMMUNITY_Host Data Models|Host Data Models]]
- [[_COMMUNITY_Vite Build Config|Vite Build Config]]
- [[_COMMUNITY_SvelteKit Config|SvelteKit Config]]
- [[_COMMUNITY_Job Data Model|Job Data Model]]
- [[_COMMUNITY_Log Data Model|Log Data Model]]
- [[_COMMUNITY_CVE Detail Model|CVE Detail Model]]
- [[_COMMUNITY_Export File Model|Export File Model]]
- [[_COMMUNITY_WebSocket Options|WebSocket Options]]
- [[_COMMUNITY_Vite Brand Asset|Vite Brand Asset]]

## God Nodes (most connected - your core abstractions)
1. `req()` - 16 edges
2. `req (HTTP helper)` - 15 edges
3. `Dashboard Page` - 12 edges
4. `App Root Component` - 11 edges
5. `Reconnaissance Page` - 9 edges
6. `WebSocketClient` - 8 edges
7. `VulnDb Page` - 8 edges
8. `fmtDate` - 5 edges
9. `wsMessages Store` - 5 edges
10. `Logs Page` - 5 edges

## Surprising Connections (you probably didn't know these)
- `Dashboard Page` --calls--> `triggerExport`  [EXTRACTED]
  src/lib/pages/Dashboard.svelte → src/lib/api.ts
- `VulnDb Page` --semantically_similar_to--> `Settings Page`  [INFERRED] [semantically similar]
  src/lib/pages/VulnDb.svelte → src/lib/pages/Settings.svelte
- `Main Entry Point` --references--> `App Root Component`  [EXTRACTED]
  src/main.ts → src/App.svelte
- `App Root Component` --calls--> `closeWebSocket`  [EXTRACTED]
  src/App.svelte → src/lib/stores/websocketStore.ts
- `App Root Component` --references--> `Navbar Component`  [EXTRACTED]
  src/App.svelte → src/lib/components/Navbar.svelte

## Hyperedges (group relationships)
- **Real-time WebSocket Update Flow** — websocketstore_wsmessages, dashboard_svelte, reconnaissance_svelte, logs_svelte, vulndb_svelte [EXTRACTED 0.95]
- **API CRUD Pattern via req helper** — api_req, api_getjobs, api_createjob, api_canceljob, api_schedulejob [EXTRACTED 1.00]
- **SPA Routing Structure** — app_svelte, navbar_svelte, dashboard_svelte, reconnaissance_svelte, logs_svelte, attacks_svelte, plugins_svelte, vulndb_svelte, settings_svelte [EXTRACTED 1.00]

## Communities (20 total, 8 thin omitted)

### Community 0 - "API Function Layer"
Cohesion: 0.13
Nodes (24): cancelJob(), createJob(), CveDetail, ExportFile, getConfig(), getCve(), getExports(), getHost() (+16 more)

### Community 1 - "Page Logic & Control Flow"
Cohesion: 0.14
Nodes (8): string, string, number, q, app, ../api, ../stores/websocketStore, ../utils

### Community 2 - "WebSocket Client Layer"
Cohesion: 0.15
Nodes (4): WebSocketClient, WebSocketOptions, connectionStatus, wsMessages

### Community 3 - "API Read Operations"
Cohesion: 0.26
Nodes (12): getConfig, getCve, getHost, getHosts, getJob, getLogsByJob, listCves, req (HTTP helper) (+4 more)

### Community 4 - "App Shell & Routing"
Cohesion: 0.22
Nodes (11): App Root Component, Attacks Page, Main Entry Point, Navbar Component, Plugins Page, WebSocketClient, closeWebSocket, connectionStatus Store (+3 more)

### Community 5 - "Dashboard & Export Views"
Cohesion: 0.28
Nodes (9): exportDownloadUrl, getExports, getJobs, getLogs, Dashboard Page, Logs Page, fmtDate, fmtResults (+1 more)

### Community 6 - "Job Lifecycle & Recon"
Cohesion: 0.4
Nodes (5): cancelJob, createJob, scheduleJob, triggerExport, Reconnaissance Page

### Community 8 - "Host Data Models"
Cohesion: 0.67
Nodes (3): Host Interface, Port Interface, Vulnerability Interface

## Knowledge Gaps
- **35 isolated node(s):** `app`, `Port`, `Vulnerability`, `Host`, `Job` (+30 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **8 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `App Root Component` connect `App Shell & Routing` to `API Read Operations`, `Dashboard & Export Views`, `Job Lifecycle & Recon`?**
  _High betweenness centrality (0.030) - this node is a cross-community bridge._
- **Why does `req (HTTP helper)` connect `API Read Operations` to `Dashboard & Export Views`, `Job Lifecycle & Recon`?**
  _High betweenness centrality (0.026) - this node is a cross-community bridge._
- **Why does `Dashboard Page` connect `Dashboard & Export Views` to `API Read Operations`, `App Shell & Routing`, `Job Lifecycle & Recon`?**
  _High betweenness centrality (0.025) - this node is a cross-community bridge._
- **What connects `app`, `Port`, `Vulnerability` to the rest of the system?**
  _35 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `API Function Layer` be split into smaller, more focused modules?**
  _Cohesion score 0.13 - nodes in this community are weakly interconnected._
- **Should `Page Logic & Control Flow` be split into smaller, more focused modules?**
  _Cohesion score 0.14 - nodes in this community are weakly interconnected._