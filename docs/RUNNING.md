# Running Decebalus

Decebalus is a single self-contained binary: the web UI and the database schema
are baked in at compile time, and the SQLite database file creates itself on
first launch. There is nothing to configure to get the UI up.

- **Web UI / API:** the server binds `0.0.0.0:8080` → open **http://localhost:8080**
- **Data:** a `data/` folder (SQLite db + encryption keys) is created next to
  wherever you run the binary. Back this folder up; deleting it resets everything.
- **Wordlists:** the bundled SecLists dictionaries are **not** inside the binary
  and **not** in the git repo — see [Wordlists](#wordlists-the-one-thing-not-baked-in).
- **Stop the server:** `Ctrl+C`.

### What is / isn't self-contained
| Piece | Shipped how | You do |
|---|---|---|
| Database schema | embedded in binary (`sqlx::migrate!`) | nothing |
| Database file + keys | auto-created in `data/` on first run | nothing |
| Web UI | embedded in binary (`--features embed-ui`) | nothing |
| **Bundled wordlists** | **on disk at `assets/seclists/` — gitignored, ~1.2 GB** | **ship separately (below)** |
| External tools (nmap, nxc, …) | must be on `PATH` | install per OS |

> **Platform reality check.** Decebalus is an *orchestrator* — the core app, web
> UI, and native brute-force modules (SSH/SMB/FTP/RDP) run on all three OSes, but
> the AD/recon features that shell out to external tools (nmap, NetExec, certipy,
> impacket, …) are Linux-native. **Linux is the first-class platform.** Windows
> and macOS run the app fine but with a reduced external-tool set. See the tool
> matrix at the bottom.

---

## Two ways to get a binary

1. **Build from source** (any OS) — clone the repo, run one script. Covered per-OS below.
2. **Ship a prebuilt binary** — build once, hand someone the single executable +
   let it create its own `data/` folder. They skip all the build prerequisites.
   **Ship the `assets/seclists/` folder alongside it** if you want bundled
   wordlists (see below) — the binary does not contain them.

Building from source needs **Rust** (https://rustup.rs) and **Node.js 18+** (for `npm`).

---

## Linux (first-class platform)

### 1. Prerequisites
```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Node.js (Debian/Ubuntu/Kali)
sudo apt update && sudo apt install -y nodejs npm

# Recommended external tools for full AD/recon features
sudo apt install -y nmap smbclient hashcat freerdp2-x11
pipx install netexec        # provides `nxc`
pipx install certipy-ad     # ADCS checks
pipx install impacket       # ntlmrelayx.py etc.
```

### 2. Build (one command)
```bash
bash decebalus-backend/scripts/build.sh
```
Output: `decebalus-backend/target/release/decebalus-backend`

### 3. Run
Raw ARP/ICMP host discovery needs raw-socket privileges. Two options:

```bash
# Option A — grant the capability once (preferred, no sudo per run):
sudo setcap cap_net_raw+ep decebalus-backend/target/release/decebalus-backend
./decebalus-backend/target/release/decebalus-backend

# Option B — run with sudo:
sudo ./decebalus-backend/target/release/decebalus-backend
```
Without either, the app still runs — it just falls back to a limited TCP probe
for host discovery instead of ARP/ICMP.

### 4. Verify
```bash
./decebalus-backend/target/release/decebalus-backend doctor   # which external tools are present
```
Then open **http://localhost:8080**.

---

## Windows

> Full ARP/ICMP scanning on Windows needs **Npcap** (https://npcap.com), and
> **building** the packet crates from source needs the Npcap SDK's `Packet.lib`
> on the linker path. If you don't need raw scanning, the app + UI + native brute
> modules still run without Npcap (limited-TCP-probe fallback).

### Easiest path: get a prebuilt binary
Building on Windows requires MSVC (Visual Studio Build Tools), Rust, Node.js, and
the Npcap SDK — a lot of setup. If someone hands you `decebalus-backend.exe`:

1. Put the `.exe` in its own folder (it will create a `data\` folder there).
2. (Optional, for raw scanning) install **Npcap** from https://npcap.com — check
   "WinPcap API-compatible mode" during install.
3. Double-click the `.exe`, or from PowerShell:
   ```powershell
   .\decebalus-backend.exe
   ```
   For raw scanning, run PowerShell **as Administrator** first.
4. Open **http://localhost:8080**.

### Building from source on Windows
```powershell
# 1. Install: Rust (https://rustup.rs), Node.js LTS (https://nodejs.org),
#    Visual Studio Build Tools (C++ workload), and the Npcap SDK (https://npcap.com/#download).
# 2. Point the linker at the Npcap SDK libs (adjust path to where you unzipped it):
$env:LIB = "C:\npcap-sdk\Lib\x64;$env:LIB"

# 3. Build the frontend, then the backend with the embedded UI:
cd decebalus-frontend
npm ci
npm run build
cd ..\decebalus-backend
cargo build --release --features embed-ui
```
Output: `decebalus-backend\target\release\decebalus-backend.exe`

> Most external orchestrated tools (NetExec, certipy, impacket, responder) target
> Linux. On Windows, prefer running Decebalus inside **WSL2** (follow the Linux
> guide there) if you want those features.

---

## macOS

Runs the same as Linux with two differences: raw scanning needs `sudo` (there is
no `setcap`), and several external tools install via Homebrew/pipx instead of apt.

### 1. Prerequisites
```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Node.js + common external tools
brew install node nmap hashcat
pipx install netexec certipy-ad impacket
```

### 2. Build (one command)
```bash
bash decebalus-backend/scripts/build.sh
```
Output: `decebalus-backend/target/release/decebalus-backend`

### 3. Run
```bash
# Raw ARP/ICMP scanning on macOS requires root (BPF access) — no setcap equivalent:
sudo ./decebalus-backend/target/release/decebalus-backend
```
Without `sudo` the app runs but falls back to the limited TCP probe for discovery.

### 4. Verify
```bash
./decebalus-backend/target/release/decebalus-backend doctor
```
Open **http://localhost:8080**.

---

## Wordlists (the one thing not baked in)

The brute-force modules use dictionaries from a **bundled SecLists subset**
(~1.2 GB, ~1100 `.txt` files) that lives at `decebalus-backend/assets/seclists/`,
**relative to wherever you run the binary**. This folder is:

- **not embedded** in the binary (it's read from disk at runtime), and
- **not in the git repo** (`assets/seclists/` is gitignored — too big to commit).

So neither `git clone` nor the single binary gives you wordlists on their own.
The app still runs without them — startup just logs
`assets/seclists not found — no bundled wordlists registered` and brute-force
attacks have no built-in dictionaries until someone uploads a custom list in the UI.

### To have bundled wordlists, do one of:
1. **Build on the same machine that has `assets/seclists/`** — run the binary from
   the repo root (or `decebalus-backend/`) so `assets/seclists/` sits next to it. This
   is the default if you built from source and don't move the binary.
2. **Ship them with a prebuilt binary** — put `assets/seclists/` in the same folder
   the binary runs from. Distribute it as a separate download / archive (it's large).
3. **Point at your own SecLists checkout** — clone SecLists and symlink or copy the
   `Passwords`, `Usernames`, and `Discovery` folders into `assets/seclists/`:
   ```bash
   git clone --depth 1 https://github.com/danielmiessler/SecLists.git
   mkdir -p decebalus-backend/assets/seclists
   cp -r SecLists/Passwords SecLists/Usernames SecLists/Discovery decebalus-backend/assets/seclists/
   ```
4. **Users bring their own** — any `.txt` uploaded in the UI is saved under
   `data/wordlists/custom/` and works without the bundled set.

---

## Optional configuration (all platforms)

Set before launching (or put in a `.env` file next to the binary):

| Variable        | Default                    | Purpose                                  |
|-----------------|----------------------------|------------------------------------------|
| `DATABASE_URL`  | `sqlite:data/decebalus.db` | Where the SQLite database lives          |
| `RUST_LOG`      | (info)                     | Log verbosity, e.g. `debug`, `trace`     |

The server always listens on `0.0.0.0:8080`.

---

## External tool support by platform

The native brute-force modules (SSH/SMB/FTP/RDP) are built into the binary and
work everywhere. These *external* tools are orchestrated only if present on `PATH`
(`decebalus-backend doctor` reports what's found):

| Tool                | Purpose                                   | Linux | macOS | Windows        |
|---------------------|-------------------------------------------|:-----:|:-----:|:--------------:|
| nmap                | port/service scan, OS & vuln detection    |  ✅   |  ✅   | ✅             |
| netexec (`nxc`)     | AD enum, spray, roasting, BloodHound      |  ✅   |  ⚠️   | WSL2           |
| smbclient           | SMB brute-force fallback                  |  ✅   |  ✅   | WSL2           |
| certipy             | ADCS misconfig checks (ESC1–ESC8)         |  ✅   |  ⚠️   | WSL2           |
| xfreerdp            | RDP brute force (NLA)                     |  ✅   |  ⚠️   | WSL2           |
| impacket            | NTLM relay (operator-run)                 |  ✅   |  ⚠️   | WSL2           |
| responder           | LLMNR/NBT-NS poisoning                    |  ✅   |  ❌   | WSL2           |
| hashcat             | offline cracking of roasted hashes        |  ✅   |  ✅   | ✅             |

✅ works · ⚠️ installable but less common/tested · WSL2 = run the Linux guide inside WSL2

---

## Legal / authorization

Decebalus is offensive security tooling. Only run it against networks and systems
you own or are explicitly authorized to test.
