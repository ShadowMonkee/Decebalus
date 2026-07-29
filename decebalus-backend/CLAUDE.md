# Backend — working rules

## Consult the knowledge graph FIRST (token discipline)

This folder has a graphify knowledge graph at `decebalus-backend/graphify-out/`. **Before searching the codebase — answering architecture/dependency questions, locating a function, tracing how modules connect, or planning a change — consult the graph first, and only drop to reading raw source when the graph doesn't have the line-level detail you need.** This saves tokens versus grepping and reading whole files.

How to use it:
- **`graphify-out/GRAPH_REPORT.md`** — start here. God nodes (most-connected abstractions like `PortScanner`, `JobExecutor`, `repository.rs`, the `Orchestrator`/rule-engine), community map (e.g. "Attack Module Registry", "Rule Engine", "Scope Lock", "NetExec AD Helpers", per-module communities), and surprising cross-module connections.
- **`graphify-out/graph.json`** — the queryable graph (nodes = functions/structs/files, edges = calls/implements/relations). Look up a node and its neighbors before opening files.
- **Query the graph** when a plain read would be broad:
  - `graphify query "<question>"` — BFS, broad context
  - `graphify path "<NodeA>" "<NodeB>"` — shortest path between two concepts
  - `graphify explain "<Node>"` — everything connected to one node

Prefer graph-derived answers for architecture, dependency, and cross-cutting questions; fall back to raw file reads only for exact line-level details the graph doesn't capture.

## Keep the graph fresh

After changing backend code, update the graph (AST-only, no LLM cost):
```
cd decebalus-backend && graphify update .
```
The graph currently covers the assumed-breach orchestrator: models (engagements/credentials/facts/findings), the `AttackModule` registry + AD modules (`ad_*`), the rule engine (`services/rules.rs`), OPSEC/scope-lock, the API layer, and the TUI.

## Build / test

`export PATH="$HOME/.cargo/bin:$PATH"` first (cargo is off the default PATH). Then `cargo test` (in-memory SQLite, no DATABASE_URL needed). TUI: `cargo build --features tui --bin decebalus-tui`. If cargo gets denied by the safety classifier, the user must add a Bash allow-rule for `cargo`.
