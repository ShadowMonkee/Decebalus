# Frontend — working rules

## Consult the knowledge graph FIRST (token discipline)

This folder has a graphify knowledge graph at `decebalus-frontend/graphify-out/`. **Before searching the codebase — answering "where is X", tracing which page uses which API call or store, understanding component/data flow, or planning a change — consult the graph first, and only drop to reading raw `.svelte`/`.ts` source when you need line-level detail the graph doesn't have.** This saves tokens versus grepping and reading whole files.

How to use it:
- **`graphify-out/GRAPH_REPORT.md`** — start here. God nodes (e.g. `req()`, `api.ts`, `WebSocketClient`) and the community map: "API Client (api.ts)", "WebSocket Store & Client", "App Shell & Routing", and one community per page (Dashboard, War Table, Engagement, Reconnaissance, Attacks, Vuln DB, Logs & History), plus "Formatting Utils".
- **`graphify-out/graph.json`** — the queryable graph (nodes = functions/components/files, edges = calls/imports/relations). Look up a node and its neighbors before opening files.
- **Query the graph** when a plain read would be broad:
  - `graphify query "<question>"` — BFS, broad context
  - `graphify path "<NodeA>" "<NodeB>"` — shortest path between two concepts
  - `graphify explain "<Node>"` — everything connected to one node

Prefer graph-derived answers for structure, dependency, and cross-cutting questions; fall back to raw file reads only for exact line-level details (markup, styles) the graph doesn't capture.

> Note: the graph is code-focused (Svelte + TypeScript via AST). Non-code assets (README, images) are intentionally not in it.

## Keep the graph fresh

After changing frontend code, update the graph (AST-only, no LLM cost):
```
cd decebalus-frontend && graphify update .
```

## Build / check

`npm run check` (svelte-check, type safety) and `npm run build` (Vite). `npm run dev` for the dev server (proxies `/api` and `/ws` to the backend on :8080).
