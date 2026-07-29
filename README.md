
# Decebalus

> A deterministic, OPSEC-aware **assumed-breach orchestrator** you run from your own attack box. Inspired by the approachable, autonomous feel of [Bjorn](https://github.com/infinition/Bjorn) — but built for real internal engagements on a laptop instead of a Pi. Name is inspired by the legendary Dacian king.

## Overview

Decebalus is a **quick-win orchestrator for the opening hour of an internal / assumed-breach engagement**. You run it from your Kali (or any Linux) box, feed it scope — a subnet, and optionally one low-privilege credential — and it drives the standard opening playbook deterministically: host discovery, service enumeration, vulnerability matching, and the AD/network quick-wins that red teamers check by hand every single engagement.

Instead of leaving you at a raw CLI, it maintains live engagement **state** and presents a glanceable **war table**: what's been found, what's high-value, and the **ranked next moves** — each with a copy-paste command. It orchestrates the tools you already trust (nmap, NetExec, smbclient, and friends) rather than reinventing them, and it stays **deterministic and rule-based** so you always know exactly what it will do to a client network.

Think of it as the friendly conductor for the first hour of a pentest: the operator just got a foothold credential and wants the canonical checklist run for them — while they think about the next step.

## Where Decebalus fits

The autonomous-orchestration space has split into two extremes and skipped the useful middle:

- **Hardware toys** (Bjorn, pwnagotchi, ESP32 Marauder) — great UX, autonomous, gamified — but locked to Pi/ESP hardware and Wi-Fi / opportunistic attacks, not internal AD engagements.
- **LLM agents** (Strix, PentestGPT, CAI) — flexible, but heavy, non-deterministic, and genuinely risky to point at a production client network.

Nothing occupies the middle: a **deterministic, rule-based, OPSEC-aware orchestrator** with Bjorn's approachable feel, wrapping the tools red teamers already rely on. NetExec is a superb engine but it's a raw CLI — no orchestration, no state, no "what next." BloodHound maps AD paths but doesn't drive the opening moves. Commercial platforms (Pentera and friends) do this but are expensive, closed, and enterprise-only.

Decebalus aims to be the free, scriptable, self-hosted **"first hour" conductor** with a genuinely nice interface and a real next-move engine.

## Project Purpose

This is a personal project with three goals:

### 1. Master Rust in depth

Decebalus is my vehicle for learning Rust for real — ownership/borrowing, async with Tokio, `Result`/`Option` error handling, sockets and concurrency, and production-grade services with Axum. I learn best by building something real, so this is the sandbox.

### 2. Understand offensive security tradecraft

By orchestrating (and in places implementing) the opening moves of an engagement, I'm internalizing the canonical assumed-breach playbook: what you check first, why, in what order, and how to do it without tripping lockouts or making noise.

### 3. Build something genuinely useful and free

A strong, free, open core is a reputation play in the AD / red-team world. The unserved slice is an opinionated, free, scriptable opener with a clean UI and a next-move engine — and that's what this is aimed at.

## What Decebalus Does

### Current Capabilities

- **Network Discovery**: Identify alive hosts via ARP/ICMP/TCP probes
- **Port Scanning**: Fast concurrent TCP connect scan across all 65 535 ports
- **Nmap Integration**: Full nmap scan with service/version detection, OS fingerprinting, and UDP scanning (see [Nmap Capabilities](#nmap-capabilities))
- **Service Detection**: Banner grabbing + heuristic fingerprinting fallback when nmap is unavailable
- **OS Detection**: Inferred from SSH banners, HTTP headers, and nmap extrainfo
- **CVE matching**: Vulnerability detection via nmap vulners, enriched from the NVD API (CVSS/severity), surfaced in host detail and the Vuln DB
- **Attack modules**: SSH, FTP, SMB, RDP brute force, plus SFTP file exfiltration — dispatched through a **pluggable module registry** (add a module by implementing one trait)
- **Autonomous operation**: A background loop that continuously discovers → scans → fingerprints → enriches (attacks strictly opt-in), Bjorn-style
- **Suggestion seed**: Maps a host's open ports to the relevant attack modules — the first step toward a full next-move engine
- **Job Management**: Queue, schedule, cancel, and track everything as background jobs with priority ordering
- **Real-time Updates**: WebSocket for live progress and phase messages
- **Historical tracking**: A timeline of new hosts, status changes, newly opened ports, and new vulnerabilities — your engagement's running state
- **Reporting**: Self-contained HTML security reports
- **Web Dashboard**: Svelte SPA with host detail, port/service table, job history, and log browser
- **REST API**: Full API for programmatic control and scripting
- **Persistent Storage**: SQLite for results, job history, and logs

### The Direction — Assumed-Breach Opening Playbook

This is where Decebalus is headed, and where the effort is now focused. The goal is to codify the canonical opening loop into a friendly, deterministic runner:

- **Credentialed engagement model** — hand Decebalus one validated credential (user/pass/hash + domain) and thread it through every module, instead of only guessing from wordlists
- **NetExec-backed AD quick-wins** — SMB signing checks, null-session / guest enumeration, share hunting, and password-policy discovery, by wrapping and parsing `nxc`
- **Credential spraying** — first-class, **lockout-aware** spray (one password across many users, throttled to policy) as distinct from loud brute force
- **ADCS misconfiguration checks** (Certipy — ESC1–8)
- **LLMNR/NBT-NS/mDNS + NTLM relay** opportunity detection
- **Kerberoasting / AS-REP roasting** and **BloodHound-style path awareness**
- **The next-move engine** — a rule set over engagement *facts* (signing state, valid creds, readable shares, roastable SPNs …) that emits **ranked findings, each with a copy-paste command** and a "war table" view of high-value targets
- **OPSEC posture** — a quiet mode, explicit lockout guards, and noise-aware scan choices

### Legacy / Optional Hardware Mode

Decebalus started life targeting a Raspberry Pi Zero 2 W with a Waveshare e-paper HAT, and that path still exists behind the `--features hardware` flag (mock renderer by default; on-device validation pending). It is no longer the primary target — Decebalus is now built to run from your own machine — but the display abstraction remains for anyone who wants the Pi appliance form factor.

## Architecture

Decebalus is built with a modular architecture designed for clarity and extensibility:

```
src/
├── main.rs           # Entry point and routing
├── api/              # HTTP endpoints
├── services/         # Business logic (scanning, jobs, orchestration, attacks)
├── models/           # Data structures
├── db/               # Database layer
└── state.rs          # Shared application state
```

Adding a new capability means implementing the `AttackModule` trait and registering it — the orchestrator, job queue, dashboard, and suggestion engine pick it up automatically. This is the extension point the AD playbook above is being built on.

**Tech Stack:**

- **Web Framework**: Axum
- **Async Runtime**: Tokio
- **Database**: SQLite with SQLx
- **Protocol**: WebSocket for real-time updates
- **Frontend WebApp**: Svelte for a minimal footprint

## Why Rust?

- **Safety**: Memory safety without garbage collection is valuable for security tooling
- **Performance**: Scanning is I/O-bound but benefits from efficient async handling
- **Concurrency**: Tokio makes parallel scanning and orchestration straightforward
- **Reliability**: The compiler catches many bugs before they reach a client network
- **Learning Curve**: Challenging enough to be educational, powerful enough to build a real tool

## Getting Started

### Prerequisites

- Rust 1.75+
- SQLite
- nmap
- Linux/macOS/WSL (a Kali VM is the intended home)
- *(for AD modules, as they land)* NetExec (`nxc`), smbclient, and friends on `$PATH`

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/decebalus.git
cd decebalus/decebalus-backend

# Create .env file
cat > .env <<'EOF'
DATABASE_URL=sqlite:data/decebalus.db
LOG_RETENTION_DAYS=30
MAX_THREADS=5
MAX_DISCOVER_THREADS=256
MAX_SCAN_CONCURRENCY=500
EOF

# Fetch dependencies and initialise the database
cargo fetch
mkdir -p data
cargo sqlx database create
cargo sqlx migrate run

# Run the application
cargo run
```

The server will start on `http://0.0.0.0:8080`

### Single-binary build (embedded UI)

`cargo build` alone serves the UI from `decebalus-frontend/dist` on disk (the
default above — convenient for frontend dev since a plain `npm run build` is
visible on the next request, no Rust rebuild needed). For a single distributable
binary with the UI baked in, run:

```bash
decebalus-backend/scripts/build.sh          # release build
decebalus-backend/scripts/build.sh --debug  # faster, for local testing
```

This builds the frontend, then compiles the backend with `--features embed-ui`.
The output (`target/release/decebalus-backend`) needs no `FRONTEND_DIR` or `dist/`
folder alongside it — just run the binary. Note: editing frontend source and
running `cargo build --features embed-ui` by hand *without* rebuilding the
frontend first will re-embed the *stale* `dist/`, since Cargo only knows to
re-embed because `build.rs` watches the `dist/` folder for changes — always go
through `scripts/build.sh` (or `npm run build` first) after a frontend edit.

### Secrets at rest

The credential store and `data/loot/` are encrypted with AES-256-GCM, keyed per
engagement via HKDF off a single master key. On first run a key is generated at
`data/master.key` (0600 perms) automatically — nothing to configure. To supply your
own instead (e.g. for backup/restore across machines), set `DECEBALUS_MASTER_KEY`
to a 32-byte hex string before starting the server. Loot referenced in a finding's
suggested command (e.g. Kerberoast hashes) is decrypted on demand with
`decebalus-backend loot decrypt <path>`.

### Nmap Capabilities

The `nmap-scan` job runs a three-phase pipeline:

| Phase | What it does | Requires |
|-------|-------------|----------|
| TCP scan | `nmap -sV -O --osscan-guess -p 1-65535` | `CAP_NET_RAW` for `-O`; falls back to `-sV` only without it |
| UDP scan | `nmap -sU --top-ports 200` | `CAP_NET_RAW`; skipped gracefully without it |
| Persist | Saves ports, services, OS info to SQLite | — |

**Enabling full capabilities without running the backend as root:**

nmap performs a hard root UID check (`geteuid() == 0`) for OS detection and UDP scanning — Linux capabilities (`setcap`) alone are not sufficient. The recommended approach is a tightly-scoped sudoers rule that allows nmap to run as root without a password prompt, while the backend process stays unprivileged:

```bash
echo "$USER ALL=(root) NOPASSWD: /usr/bin/nmap" | sudo tee /etc/sudoers.d/decebalus-nmap
```

This unlocks:
- **SYN scan** (`-sS`) — nmap chooses this automatically as root; faster and quieter than TCP connect
- **OS fingerprinting** (`-O`) — dedicated OS detection engine, more reliable than banner heuristics
- **UDP scanning** (`-sU`) — discovers services invisible to TCP: SNMP (161), DNS (53), NTP (123), DHCP (67/68), SSDP (1900), etc.

Without the sudoers rule the nmap-scan job still completes with full TCP service detection — OS fingerprinting and UDP scanning are skipped with a log warning and the command above is printed as a hint.

### Basic Usage

```bash
# Create a network discovery job
curl -X POST http://localhost:8080/api/jobs \
  -H "Content-Type: application/json" \
  -d '{"job_type": "discovery", "target": "192.168.68.0/24"}'

# List all jobs
curl http://localhost:8080/api/jobs

# List discovered hosts
curl http://localhost:8080/api/hosts

# Connect to WebSocket for real-time updates
websocat ws://localhost:8080/ws
```

## Learning Objectives

Through building Decebalus, I'm developing expertise in:

### Rust
- Systems-level programming, async Rust patterns, web framework development, database integration, custom error types

### Cybersecurity
- TCP/IP fundamentals, host discovery and enumeration, port scanning, service identification, vulnerability assessment, and the canonical assumed-breach opening playbook (AD quick-wins, credential spraying, relay/roasting opportunities)

### Software Engineering
- Modular architecture, API design, real-time data streaming, concurrent task management, deterministic orchestration, testing

## Ethical Considerations

This tool is designed for:

- ✅ Authorized security testing and sanctioned red-team engagements
- ✅ Personal network monitoring
- ✅ Educational purposes (CRTP/CRTE/OSEP-style learning of the canonical opening sequence)
- ✅ Learning and experimentation

This tool should **NOT** be used for:

- ❌ Unauthorized network scanning
- ❌ Attacking systems you don't own or lack written authorization to test
- ❌ Illegal activities

Decebalus is deterministic and scope-driven by design specifically so an operator always stays in control of what touches a client network. Always ensure you have explicit, written permission before scanning or attacking any network.

## Project Status

**Current Phase**: Recon + orchestration engine working; pivoting toward the assumed-breach AD playbook and next-move engine.

- [x] API structure and routing
- [x] Database integration (SQLite)
- [x] Job management system with priority and scheduling
- [x] Network discovery (ARP/ICMP/TCP)
- [x] Fast concurrent port scanning (all 65 535 TCP ports)
- [x] Nmap integration — service detection, OS fingerprinting, UDP scan
- [x] Service fingerprinting and banner grabbing fallback
- [x] WebSocket real-time progress streaming
- [x] Web dashboard (host detail, job history, log browser)
- [x] Vulnerability matching / CVE lookup (nmap vulners + NVD enrichment)
- [x] Attack modules — SSH, FTP, SMB, RDP brute force + SFTP file steal
- [x] Pluggable attack-module registry (trait-based extension point)
- [x] Autonomous operation loop (recon-only by default)
- [x] Port → attack-module suggestion seed
- [x] Historical tracking / change-detection timeline
- [x] HTML report export
- [x] Credentialed engagement model (engagements + credential store, threaded through modules)
- [x] NetExec-backed AD quick-wins (SMB signing, null-session, share hunting, password policy)
- [x] Lockout-aware credential spraying
- [x] ADCS (Certipy) + relay/roasting (Kerberoast/AS-REP) + BloodHound collection
- [x] Next-move rule engine + "war table" view with copy-paste commands
- [x] OPSEC / quiet mode + jitter + scope-lock + lockout guards
- [x] Structured real-time events, native TUI, dependency doctor, optional token auth
- [x] Secrets-at-rest encryption for the credential store + loot
- [x] Single-binary frontend embedding (broader on-device validation still pending)

## Roadmap

### Phase 1 — Recon foundation *(done)*
Network utilities, host discovery, parallel port scanning, service detection.

### Phase 2 — Enrichment *(done)*
Vulnerability assessment, OS fingerprinting, nmap integration, autonomous loop.

### Phase 3 — Assumed-breach opener *(done)*
Credentialed model, NetExec-backed AD quick-wins, lockout-aware spraying, ADCS/roasting/BloodHound, and the tool-wrapping module layer.

### Phase 4 — The next-move engine *(done)*
A deterministic rule engine over engagement facts that produces ranked, copy-paste next moves, surfaced in a glanceable web war table and a native TUI.

### Phase 5 — Hardening & team *(current)*
Secrets-at-rest encryption, single-binary packaging, then shared engagement state, multi-operator deconfliction, and richer client-ready reporting.

## Assumed-Breach Quickstart

The opening hour of an internal engagement, driven from the web **War Table** (or the terminal one):

1. **Check tooling** — `cargo run -- doctor` reports which external tools are present and how to install the missing ones.
2. **Create an engagement** — on the *Engagement* page, enter your scope CIDRs (this enables scope-lock) and, if you have one, a starting low-priv credential. It becomes the active engagement.
3. **Discover + enumerate** — kick off discovery/port-scan; the read-only AD enum modules (`ad-smb-enum`, `ad-null-session`, `ad-password-policy`) record facts (signing state, users, shares, lockout policy).
4. **Read the war table** — the rule engine ranks the next moves. Read-only moves auto-run (in autonomous mode); risky ones appear as ranked findings with a **copy-paste command** and a one-click **Run**.
5. **Escalate** — validated credentials unlock the credentialed playbook (Kerberoast, AS-REP, ADCS/Certipy, BloodHound). Spraying is **lockout-aware** — it refuses if the discovered policy makes a single attempt unsafe (override with `force`).

Everything stays **deterministic and scope-locked**: a module refuses any target outside the engagement's declared CIDRs.

### Tool Dependencies

Decebalus orchestrates tools you already trust rather than reimplementing them. Run `cargo run -- doctor` to see live status.

| Tool | Used for | Install |
|------|----------|---------|
| `nmap` | port/service/OS/vuln scanning | `apt install nmap` |
| `nxc` (NetExec) | AD enum, spray, roasting, BloodHound | `pipx install netexec` |
| `certipy` | ADCS ESC1–ESC8 checks | `pipx install certipy-ad` |
| `smbclient` | SMB brute-force fallback | `apt install smbclient` |
| `xfreerdp` | RDP brute force | `apt install freerdp2-x11` |
| `hashcat` | cracking roasted hashes (offline) | `apt install hashcat` |
| `impacket` / `responder` | operator-run relay/poisoning (surfaced as findings) | `pipx install impacket` |

### Operating It

- **Web war table** — `npm run dev` in `decebalus-frontend/` (or build it and serve statically), then visit the War Table and Engagement pages.
- **Terminal war table** — `cargo run --features tui --bin decebalus-tui` (point it at a running server via `DECEBALUS_URL`). Keys: `⏎` run, `d` dismiss, `e` re-evaluate, `r` refresh, `q` quit.
- **Optional auth** — set `DECEBALUS_TOKEN` to require `Authorization: Bearer <token>` on every request (the server now holds credentials and loot). The TUI reads the same variable.
- **OPSEC** — `opsec_quiet` adds jitter and prefers stealthier options; `spray_lockout_buffer` tunes the spray safety margin. Both are runtime settings (hot-reloaded).

## Contributing

This is a personal learning project, but feedback and discussions are welcome — especially from anyone with deep AD / red-team tradecraft. If you're interested in Rust best practices, the assumed-breach playbook, or system design, feel free to open issues or reach out.

## Resources & Inspiration

- [Bjorn](https://github.com/infinition/Bjorn) — the original inspiration for the approachable, autonomous feel
- [NetExec](https://github.com/Pennyw0rth/NetExec) — the AD engine Decebalus orchestrates
- [The Rust Book](https://doc.rust-lang.org/book/)
- [Tokio Documentation](https://tokio.rs/)
- [Network Scanning with Nmap](https://nmap.org/book/)

## License

Apache License Version 2.0 - See LICENSE file for details

## Author

ShadowMonkee

---

  **Remember what Uncle Ben said**: With great power comes great responsibility. Use this tool ethically and **legally**.
</content>
</invoke>
