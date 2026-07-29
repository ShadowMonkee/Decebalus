# Graph Report - .  (2026-07-29)

## Corpus Check
- Corpus is ~12,215 words - fits in a single context window. You may not need a graph.

## Summary
- 108 nodes · 170 edges · 16 communities (10 shown, 6 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 4 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_API Request Helpers|API Request Helpers]]
- [[_COMMUNITY_API Client (api.ts)|API Client (api.ts)]]
- [[_COMMUNITY_WebSocket Store & Client|WebSocket Store & Client]]
- [[_COMMUNITY_Attacks Page|Attacks Page]]
- [[_COMMUNITY_Engagement  Settings Pages|Engagement / Settings Pages]]
- [[_COMMUNITY_Vuln DB Page|Vuln DB Page]]
- [[_COMMUNITY_App Shell & Routing|App Shell & Routing]]
- [[_COMMUNITY_Logs & History Pages|Logs & History Pages]]
- [[_COMMUNITY_Dashboard Page|Dashboard Page]]
- [[_COMMUNITY_Job & Export Triggers|Job & Export Triggers]]
- [[_COMMUNITY_App Entrypoint|App Entrypoint]]

## God Nodes (most connected - your core abstractions)
1. `req()` - 28 edges
2. `WebSocketClient` - 8 edges
3. `refresh()` - 5 edges
4. `createJob()` - 4 edges
5. `getJobs()` - 3 edges
6. `getHosts()` - 3 edges
7. `cancelJob()` - 3 edges
8. `createAttackJob()` - 3 edges
9. `launch()` - 3 edges
10. `handleCancel()` - 3 edges

## Surprising Connections (you probably didn't know these)
- `handleCancel()` --calls--> `cancelJob()`  [INFERRED]
  src/lib/pages/Attacks.svelte → src/lib/api.ts
- `refresh()` --calls--> `getJobs()`  [INFERRED]
  src/lib/pages/Attacks.svelte → src/lib/api.ts
- `refresh()` --calls--> `getHosts()`  [INFERRED]
  src/lib/pages/Attacks.svelte → src/lib/api.ts
- `launch()` --calls--> `createAttackJob()`  [INFERRED]
  src/lib/pages/Attacks.svelte → src/lib/api.ts

## Communities (16 total, 6 thin omitted)

### Community 0 - "API Request Helpers"
Cohesion: 0.1
Nodes (20): createEngagement(), dismissFinding(), getActiveEngagement(), getConfig(), getCredentials(), getCve(), getEngagements(), getExports() (+12 more)

### Community 1 - "API Client (api.ts)"
Cohesion: 0.11
Nodes (17): activateEngagement(), cancelJob(), CreateEngagementBody, Credential, CveDetail, Engagement, ExportFile, Finding (+9 more)

### Community 2 - "WebSocket Store & Client"
Cohesion: 0.12
Nodes (6): WebSocketClient, WebSocketOptions, connectionStatus, WsEvent, wsEvents, wsMessages

### Community 3 - "Attacks Page"
Cohesion: 0.18
Nodes (11): createAttackJob(), getHosts(), getJobs(), handleCancel(), idx, jobId, launch(), refresh() (+3 more)

### Community 11 - "Job & Export Triggers"
Cohesion: 0.67
Nodes (3): createJob(), triggerExport(), triggerReport()

## Knowledge Gaps
- **29 isolated node(s):** `app`, `Port`, `Vulnerability`, `Host`, `Job` (+24 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **6 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `req()` connect `API Request Helpers` to `Job & Export Triggers`, `API Client (api.ts)`, `Attacks Page`?**
  _High betweenness centrality (0.110) - this node is a cross-community bridge._
- **Why does `cancelJob()` connect `API Client (api.ts)` to `API Request Helpers`, `Attacks Page`?**
  _High betweenness centrality (0.072) - this node is a cross-community bridge._
- **What connects `app`, `Port`, `Vulnerability` to the rest of the system?**
  _29 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `API Request Helpers` be split into smaller, more focused modules?**
  _Cohesion score 0.1 - nodes in this community are weakly interconnected._
- **Should `API Client (api.ts)` be split into smaller, more focused modules?**
  _Cohesion score 0.11 - nodes in this community are weakly interconnected._
- **Should `WebSocket Store & Client` be split into smaller, more focused modules?**
  _Cohesion score 0.12 - nodes in this community are weakly interconnected._