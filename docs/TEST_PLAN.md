# Decebalus — Manual QA Test Plan

Hands-on checklist to verify every feature works before calling the MVP done.
Run through it top to bottom; sections build on each other's state (discovered
hosts, an active engagement, credentials, findings). Commands assume you're in
`decebalus-backend/` unless noted, and use `curl` + `jq` — install `jq` if you
don't have it (`brew install jq` / `apt install jq`).

Set once per shell session:
```bash
export BASE=http://localhost:8080
```

---

## 1. Setup & doctor check

- [ ] `cargo build` — exits 0, no warnings you don't recognize.
- [ ] `cargo test` — all tests pass (expect 60+ across unit + integration suites).
- [ ] `cargo build --features tui --bin decebalus-tui` — builds clean.
- [ ] `cargo build --features embed-ui` — builds clean (needs `decebalus-frontend/dist` to exist first — see §18 if it's missing).
- [ ] `cargo run -- doctor` — prints a table of external tools (nmap, nxc, smbclient, certipy, xfreerdp, bloodhound-python, ntlmrelayx.py, responder, hashcat) with ✓/✗ and install hints. Expected: at least `nmap` shows ✓ if installed; missing tools show a `pipx install ...` / `apt install ...` hint, not a crash.
- [ ] Start the server: `cargo run`. Expect log line `Server listening on 0.0.0.0:8080` and no panic.
- [ ] `ls data/` — `decebalus.db` (and `decebalus.db-wal`/`-shm` once something writes) now exist.
- [ ] `curl -s $BASE/api/jobs | jq` — returns `[]` (or existing jobs) with HTTP 200, proving the API + DB are wired up.

---

## 2. Network discovery + port scanning

- [ ] Discover your own subnet: `curl -s -X POST $BASE/api/jobs -d '{"job_type":"discovery","target":"self"}' -H 'Content-Type: application/json' | jq`
  Expected: `201`, a `Job` with `status: "queued"`.
- [ ] Poll `curl -s $BASE/api/jobs/<id> | jq` until `status: "completed"`. `results` (a JSON string) contains `hosts_found`.
- [ ] `curl -s $BASE/api/hosts | jq length` — at least 1 host (your own machine / gateway).
- [ ] Full port scan on one discovered host: `curl -s -X POST $BASE/api/jobs -d '{"job_type":"port-scan","target":"<ip>"}' -H 'Content-Type: application/json' | jq`. Expect completion with `total_ports_found` reflecting real open ports (compare against `nc -zv <ip> <port>` for a known-open one).
- [ ] Port-scan with no target (`{"job_type":"port-scan"}`) — scans *all* discovered hosts; `hosts_scanned` in the result matches your host count.
- [ ] Invalid target rejected: `curl -s -X POST $BASE/api/jobs -d '{"job_type":"port-scan","target":"not-an-ip"}' -H 'Content-Type: application/json'` → `400` with `{"error":"Invalid IP address: not-an-ip"}`.
- [ ] Nmap scan (service/version + OS detection + UDP): `curl -s -X POST $BASE/api/jobs -d '{"job_type":"nmap-scan","target":"<ip>"}' -H 'Content-Type: application/json' | jq`. On completion, `curl -s $BASE/api/hosts/<ip> | jq '.ports, .os'` shows service banners and (if run with `CAP_NET_RAW`/root) an OS guess.
- [ ] Without `CAP_NET_RAW` (plain user), nmap falls back to `-sV` only — job still completes (doesn't error) per README's documented fallback.
- [ ] **UI**: Dashboard/Reconnaissance page (`decebalus-frontend/src/lib/pages/Reconnaissance.svelte`) — trigger a discovery + scan from the buttons, watch the host table populate live.

---

## 3. Service fingerprinting / banner grabbing fallback

- [ ] With `nmap` temporarily off `PATH` (e.g. `PATH=/usr/bin cargo run` in a shell without nmap), run a `port-scan` against a host running a plain-text service (e.g. an SSH server on 22). Expect the host's `banners` array (`curl -s $BASE/api/hosts/<ip> | jq .banners`) to contain a grabbed banner string (e.g. `SSH-2.0-...`) instead of nmap's richer version info.
- [ ] Confirm no crash/hang when a port refuses banners (e.g. a filtered port) — job still completes.

---

## 4. CVE matching (nmap vulners + NVD enrichment)

- [ ] Run an `nmap-scan` against a host with an old, vulnerable service if you have one in a lab (or any host — nmap's `vulners` script only fires on version-fingerprinted services).
- [ ] `curl -s $BASE/api/hosts/<ip> | jq '.vulnerabilities'` — if nmap found CVEs, entries appear here with a `detail` field (null until NVD-enriched).
- [ ] Optionally set `NVD_API_KEY` (or POST it via `/api/config`, see §Settings below) to raise NVD's rate limit, then:
  `curl -s -X POST $BASE/api/cve/sync | jq` → `201`, a queued `cve-sync` job.
- [ ] After it completes: `curl -s $BASE/api/hosts/<ip> | jq '.vulnerabilities[0].detail'` — now populated with CVSS score/severity/references (not `null`).
- [ ] `curl -s $BASE/api/cve | jq length` — locally cached CVE records grow.
- [ ] `curl -s $BASE/api/cve/CVE-2021-44228 | jq` — direct lookup (fetches+caches if not already local). Malformed ID rejected: `curl -s $BASE/api/cve/not-a-cve` → `400`.
- [ ] **UI**: VulnDb page shows the same cached CVEs with CVSS/severity.

---

## 5. Job management

- [ ] Create, list, get: covered above. `curl -s $BASE/api/jobs | jq 'length'` grows with each job.
- [ ] **Note**: there's no `priority` field on job creation — every API-created job is `NORMAL`; only `/api/findings/{id}/run` (§13) creates a `HIGH`-priority job. Verify: `curl -s $BASE/api/jobs/<id> | jq .priority` → `"NORMAL"` for a plain-created job.
- [ ] Schedule a job for the near future: `curl -s -X POST $BASE/api/jobs/schedule -d "{\"job_type\":\"discovery\",\"target\":\"self\",\"scheduled_at\":$(($(date +%s)+60))}" -H 'Content-Type: application/json' | jq`. Expect `201`, `status: "scheduled"`.
- [ ] Missing `scheduled_at` on the schedule endpoint → `400` (`"scheduled_at is required for scheduled jobs"`).
- [ ] Wait past the scheduled time; job auto-transitions to `queued`→`running`→`completed` (poll `/api/jobs/<id>`).
- [ ] Cancel: create a job, then immediately `curl -s -X POST $BASE/api/jobs/<id>/cancel | jq` → `200`, and `GET /api/jobs/<id>` shows `status: "cancelled"`. Cancelling an already-completed job → `400` (`"Job cannot be cancelled"`).
- [ ] Get a nonexistent job id → `404`.
- [ ] **Restart resume**: start a long job (e.g. `nmap-scan` on all hosts), kill the server mid-run (`Ctrl+C` or `kill`), restart `cargo run`. Log should show `Found N unfinished jobs. Resuming...` and the job re-runs to completion.
- [ ] **UI**: Dashboard job history table reflects all of the above in real time.

---

## 6. WebSocket real-time updates

- [ ] `websocat ws://localhost:8080/ws` (or `wscat -c ws://localhost:8080/ws`) in one terminal.
- [ ] In another terminal, create a job (`discovery` or `port-scan`). Expect to see `job_queued:...`, `job_running:...`, `scan_progress:...`, `job_completed:...` text frames streamed live.
- [ ] Trigger a credential find (any brute-force hit, §7) — expect a `cred_found:domain\user` frame.
- [ ] Confirm closing the tab/client (`Ctrl+C` on websocat) doesn't crash the server (check `cargo run`'s console — should log "WebSocket connection closed", not panic).
- [ ] **UI**: any page — open browser dev tools → Network → WS frame, confirm the same messages arrive and drive live UI updates (job status badges, log tail).

---

## 7. Legacy attack modules (SSH/FTP/SMB/RDP brute, SFTP file steal)

Needs a lab target — spin up a throwaway SSH/FTP/SMB/RDP service (e.g. a Docker container) you're authorized to test against, with a known weak credential to prove a real "hit."

- [ ] SSH brute: `curl -s -X POST $BASE/api/jobs -d '{"job_type":"ssh-brute","config":{"target":"<ip>","usernames":["root"],"passwords":["<known-weak-pw>","wrongpw"]}}' -H 'Content-Type: application/json' | jq`. On completion, check `/api/jobs/<id>` results mention the hit, and `curl -s $BASE/api/logs | jq` shows attempts.
- [ ] Missing required `target` → `400` (`"config.target is required for ssh-brute"`).
- [ ] FTP brute: same shape with `"job_type":"ftp-brute"` against an FTP target.
- [ ] SMB brute: `"job_type":"smb-brute"`, config `{"target":..., "domain":"", "usernames":[...], "passwords":[...]}`.
- [ ] RDP brute: `"job_type":"rdp-brute"` (needs `xfreerdp`/`xfreerdp3` on PATH — `doctor` confirms). Without it installed, expect a clean failed-job error, not a crash.
- [ ] No inline wordlist + no `wordlist_path` → falls back to the built-in default username/password lists (`DEFAULT_USERNAMES`/`DEFAULT_PASSWORDS` in `services/attacks/mod.rs`) — confirm a job with empty `config` (only `target`) still runs (will just take longer / likely miss on a hardened target).
- [ ] File steal (SFTP exfil) — needs a real SSH/SFTP credential:
  `curl -s -X POST $BASE/api/jobs -d '{"job_type":"file-steal","config":{"target":"<ip>","username":"<u>","password":"<p>","remote_path":"/etc/hostname"}}' -H 'Content-Type: application/json' | jq`
  On completion, results include `local_path` and a `preview` of the file's first bytes.
  - [ ] **Loot encryption check**: `cat <local_path>` (the path from the result) — must NOT show the plaintext file contents (it's AES-256-GCM ciphertext now). `file <local_path>` shows binary/data, not text.
  - [ ] `decebalus-backend loot decrypt <local_path>` — prints the real file contents (matches the `preview` field from the job result).
  - [ ] 10 MB size guard: try stealing a file >10 MB → job fails with `"File exceeds 10 MB limit..."`.
- [ ] **UI**: Attacks page — launch each of the above from the form, watch results populate.

---

## 8. Historical tracking / change-detection timeline

- [ ] `curl -s $BASE/api/history | jq` — after the discovery/scan runs above, expect `host_new`, `host_up`, and `port_opened` events.
- [ ] Re-run discovery/port-scan on the *same* host with no changes — no new events for it (idempotent; `re_upserting_unchanged_host_produces_no_duplicate_events` is the automated test for this).
- [ ] Open a new port on a test host (e.g. start a listener) and re-scan — a fresh `port_opened` event appears.
- [ ] `curl -s "$BASE/api/history?limit=5" | jq length` → exactly 5 (or fewer if history is shorter). `?limit=0` clamps to 1, `?limit=99999` clamps to 500 (per `.clamp(1, 500)`).
- [ ] Trigger a new CVE detection (§4) — a `vuln_new` event appears with a `severity`.
- [ ] **UI**: History page shows the same timeline, newest first.

---

## 9. HTML report export

- [ ] `curl -s -X POST $BASE/api/jobs -d '{"job_type":"report"}' -H 'Content-Type: application/json' | jq` → completes; results include `file_path` like `data/exports/report_<timestamp>.html`.
- [ ] Open that file directly in a browser (`open data/exports/report_*.html` on macOS) — self-contained HTML (no external assets needed), showing hosts, vulnerabilities, findings, and the credential vault (values shown are the decrypted plaintext, not ciphertext — confirm this looks right, not garbled).
- [ ] **Note**: reports are `.html` and are *not* listed by `/api/exports` (that endpoint only serves `.json` — the separate `export` job type below). Verify: `curl -s $BASE/api/exports | jq` does **not** include the report file.
- [ ] Data export (raw JSON dump): `curl -s -X POST $BASE/api/jobs -d '{"job_type":"export"}' -H 'Content-Type: application/json' | jq` → completes; `data/exports/export_<timestamp>.json` created.
- [ ] `curl -s $BASE/api/exports | jq` — now lists that `export_*.json` file (newest first) with `filename`, `size`, `modified_at`.
- [ ] `curl -s -OJ $BASE/api/exports/<filename>` — downloads with correct `Content-Disposition`; diff against the file on disk (`data/exports/<filename>`) — identical.
- [ ] Path traversal rejected: `curl -s $BASE/api/exports/..%2F..%2Fetc%2Fpasswd` → `400`. Non-`.json` filename → `400`. Nonexistent filename → `404`.

---

## 10. Engagement model, scope-lock, and credential store

- [ ] Create an engagement with a tight scope:
  `curl -s -X POST $BASE/api/engagements -d '{"name":"lab-1","scope_cidrs":["10.0.0.0/24"],"domain":"acme.local","dc_ip":"10.0.0.5","username":"jdoe","password":"Summer2026!"}' -H 'Content-Type: application/json' | jq`
  → `201`; note the returned `id`. It's now the active engagement (`curl -s $BASE/api/engagements/active | jq` returns it).
- [ ] Invalid CIDR rejected: `{"name":"x","scope_cidrs":["not-a-cidr"]}` → `400`.
- [ ] Empty name rejected → `400`.
- [ ] `curl -s $BASE/api/engagements | jq` — lists it, newest first.
- [ ] **Scope-lock enforcement**: with `lab-1` active (scope `10.0.0.0/24`), create a job against an out-of-scope target, e.g. `curl -s -X POST $BASE/api/jobs -d '{"job_type":"port-scan","target":"8.8.8.8"}' -H 'Content-Type: application/json' | jq` — job is created (`201`) but transitions straight to `failed` with results `"Refused: target 8.8.8.8 is outside the engagement scope"`. Confirm via `GET /api/jobs/<id>`.
- [ ] An in-scope target (`10.0.0.x`) is accepted and runs normally.
- [ ] Create a second engagement with **no** `scope_cidrs` and activate it (`POST /api/engagements/{id}/activate`) — scope-lock becomes permissive again (out-of-scope job from above now runs). Confirms the "no engagement / empty scope ⇒ permissive" policy.
- [ ] Reactivate `lab-1`: `curl -s -X POST $BASE/api/engagements/<lab-1-id>/activate | jq` → `{"message":"activated"}`. Activating an unknown id → `404`.
- [ ] **Credential vault**: `curl -s $BASE/api/credentials | jq` — shows the `jdoe`/`Summer2026!` starting credential created with the engagement, with `secret` shown as **plaintext** to the operator (this is the whole point of transparent decryption).
- [ ] **Encryption-at-rest verification** (the core check for this feature):
  ```bash
  sqlite3 data/decebalus.db "select username, secret, secret_hash from credentials where username='jdoe';"
  ```
  `secret` must be a base64 blob (NOT `Summer2026!` in plaintext) and `secret_hash` a 64-char hex string. Compare against the API's plaintext response — they must differ (ciphertext in DB vs. plaintext over the API).
  - [ ] Re-add the *same* credential (`username`+`password`) again for the same engagement — `add_credential`'s `ON CONFLICT` upsert fires (no duplicate row): `sqlite3 data/decebalus.db "select count(*) from credentials where username='jdoe';"` → `1`.
- [ ] Trigger a real credential discovery (e.g. an SSH-brute hit from §7, or `ad-spray`/`ad-cred-validate` in §12) and confirm it also lands encrypted the same way.

---

## 11. AD quick-win enumeration modules (read-only)

These wrap NetExec (`nxc`) and need either a real AD lab (small Samba-AD, a
Windows Server + DC VM, or a kit like **DetectionLab** or **GOAD**) or at
least an SMB host to point at. Full behavior against a *domain controller*
can't be honestly verified without one — the checklist below focuses on
wiring (job creation, graceful tool-missing handling, facts/findings
persistence), which is what's testable without a lab. Parsing logic itself
already has automated coverage — no live target needed to trust it:
  - `ad_smb_enum::tests::parses_signing_domain_and_os`, `::ignores_non_host_lines`
  - `ad_null_session::tests::detects_null_session_and_shares`, `::parses_and_dedups_users`
  - `ad_password_policy::tests::parses_lockout_policy`, `::none_threshold_means_no_lockout`
  - `ad_share_hunt::tests::flags_policy_and_loot_shares`

- [ ] Without `nxc`/`netexec` on `PATH`: `curl -s -X POST $BASE/api/jobs -d '{"job_type":"ad-smb-enum","config":{"target":"10.0.0.5"}}' -H 'Content-Type: application/json' | jq`. Job completes → `failed` with a clear message ("NetExec (nxc) not found — install it...") — not a crash, not a hang. Same check for `ad-null-session`, `ad-share-hunt` (also needs `username`+`password` per its `requires_cred: true`), `ad-password-policy`.
- [ ] With `nxc` installed and a real SMB/AD host in scope:
  - `ad-smb-enum` (`config: {target}`, optional `username`/`password`/`domain`) → completes; `curl -s $BASE/api/history | jq` unaffected but facts land — verify via `sqlite3 data/decebalus.db "select subject_id, key, value from facts where key in ('smb_signing','smbv1','os','domain','hostname');"`.
  - `ad-null-session` (`config: {target}`) → facts `null_session`, `users`, `shares`, `readable_shares` populated (check via the same `facts` table query, `key='null_session'` etc.).
  - `ad-password-policy` (`config: {target}`) → facts `lockout_threshold`, `lockout_window_minutes`, `min_pw_length` populated. This is the input the spray lockout guard (§14) depends on — do this before testing `ad-spray`.
  - `ad-share-hunt` (`config: {target, username, password}` — `requires_cred: true`) → facts `readable_shares`/`interesting_shares`; if SYSVOL/NETLOGON readable, a `gpp:<ip>` finding appears in `/api/findings` (§13) with a `nxc ... -M gpp_password` suggested command.
- [ ] Missing `required_config` on any of these → `400` with `"config.<field> is required for <job-type>"` (generic validation from `parse_job_from_request` — try omitting `target` on `ad-smb-enum`).
- [ ] `curl -s $BASE/api/modules | jq` — confirm all 16 modules are listed with correct `job_type`, `required_config`, `safety` (`read_only` for these four).

---

## 12. Credentialed AD attacks + loot decryption

Same lab-environment caveat as §11 — `ad-spray`, `ad-cred-validate`,
`ad-kerberoast`, `ad-asrep`, `ad-adcs`, `ad-relay-recon`, `ad-bloodhound` all
need a real domain (or NetExec/Certipy installed to at least prove graceful
tool-missing errors). Parser unit tests already cover the output-parsing
logic without a live target:
  - `ad_spray::tests::lockout_safety_leaves_a_buffer`, `::parses_spray_hits_and_admin`
  - `ad_cred_validate::tests::detects_success_and_admin`
  - `ad_kerberoast::tests::extracts_krb5tgs_hashes`
  - `ad_relay_recon::tests::selects_only_signing_disabled_hosts`
  - `ad_adcs::tests::parses_esc_vulnerabilities`
  - `ad_bloodhound::tests::extracts_zip_path`

- [ ] `ad-cred-validate` (`config: {target, username, password|hash, domain}`) against a known-good and a known-bad credential — completes either way; a valid admin credential produces a `valid_cred` fact and (via the rule engine, §13) an "Administrative access as ..." finding.
- [ ] `ad-spray` — run `ad-password-policy` first (§11) so a lockout threshold fact exists.
  - [ ] Tight lockout (threshold ≤ `spray_lockout_buffer`+1, default buffer 1): `curl -s -X POST $BASE/api/jobs -d '{"job_type":"ad-spray","config":{"target":"10.0.0.5","password":"Spring2026!"}}' -H 'Content-Type: application/json' | jq` → job completes → `failed`, message `"Spray refused: lockout threshold ... Re-run with force=true to override."` — **no attempt was actually made** (this is the safety guard, §14 covers it in depth).
  - [ ] Same request with `"config":{...,"force":true}` → proceeds despite the tight policy.
  - [ ] With `"config.users":["alice","bob"]"` supplied explicitly, spray uses that list instead of a `users` fact.
  - [ ] Any hit is recorded via `record_credential` — verify encrypted in the DB exactly like §10.
- [ ] `ad-kerberoast` (`config: {target, username, password, domain?}`) — on a domain with SPN accounts, completes with `hashes > 0`; a `kerberoast:<target>` finding appears with `suggested_command` like:
  `hashcat -m 13100 <(decebalus-backend loot decrypt data/loot/<eng-id>/...) /usr/share/wordlists/rockyou.txt --force`
  - [ ] **Loot encryption check**: `cat data/loot/<eng-id>/<target>_*_kerberoast.txt` — must NOT show a readable `$krb5tgs$...` hash (binary ciphertext).
  - [ ] `decebalus-backend loot decrypt data/loot/<eng-id>/<target>_*_kerberoast.txt` — prints the real `$krb5tgs$...` hash(es).
  - [ ] Copy-paste the finding's `suggested_command` verbatim into a shell with `hashcat` installed — it should actually run (process substitution feeds the decrypted hash straight in; no manual decrypt step needed).
- [ ] `ad-asrep` (`config: {target, username, password, domain?}`) — same pattern as kerberoast but `$krb5asrep$` hashes, `-m 18200`, finding `asrep:<target>`.
- [ ] `ad-adcs` (`config: {target, username, password, domain}` — all required) — needs Certipy; without it installed, expect a clean tool-missing failure (`require_binary` hint). With it and a vulnerable template, `adcs_present`/`adcs_vulns` facts land.
- [ ] `ad-relay-recon` (no required config — reads `smb_signing` facts from earlier `ad-smb-enum` runs) — `curl -s -X POST $BASE/api/jobs -d '{"job_type":"ad-relay-recon","config":{}}' -H 'Content-Type: application/json' | jq`. With ≥1 signing-disabled host on record, produces a `relay-targets` finding with loot at `data/loot/<eng-id>/relay_*_targets.txt`:
  - [ ] `cat` it — ciphertext, not a readable IP list.
  - [ ] `decebalus-backend loot decrypt <path>` — prints the real newline-separated IP list.
  - [ ] The finding's `suggested_command` includes `ntlmrelayx.py -tf <(decebalus-backend loot decrypt ...) -smb2support -i`.
  - [ ] With zero signing-disabled hosts on record, result is `{"relay_targets": []}` — no finding raised.
- [ ] `ad-bloodhound` (`config: {target, username, password, domain}`, optional `dns_server`) — needs `nxc`'s BloodHound collection; on success, `bloodhound_collected` fact recorded and a zip path in the result (per `extracts_zip_path`).
- [ ] Confirm every AD-attack loot file lives under `data/loot/<engagement-id>/...` (not the bare `data/loot/`), matching the encrypted-loot directory scheme.

---

## 13. Next-move rule engine + war table

- [ ] After a mix of the above (some hosts with SMB, some without facts, maybe a validated credential), `curl -s $BASE/api/findings | jq` — findings appear ranked by `value_score` descending is *not* guaranteed by the endpoint itself, but higher-value findings (e.g. `admin:<user>` at 95) should be present once earned.
- [ ] `curl -s -X POST $BASE/api/engine/run | jq` → `{"findings": N}` — manually re-triggers a rule pass; re-running with no new facts should not create duplicates (`dedup_key` upsert — check row count stays stable via `sqlite3 data/decebalus.db "select count(*) from findings;"` before/after).
- [ ] Freshly-scanned SMB host with no `smb_signing` fact yet → an auto-runnable `enum-smb:<ip>` finding (`auto_runnable: true`, `job_type: "ad-smb-enum"`). If autonomous mode is on (§ Orchestrator below), it self-runs; otherwise:
  - [ ] `curl -s -X POST $BASE/api/findings/<id>/run | jq` → `201`, a new `HIGH`-priority job created with the finding's `job_config`; the finding's `status` flips to `"running"` (`GET /api/findings` confirms).
- [ ] Dismiss a finding: `curl -s -X POST $BASE/api/findings/<id>/dismiss | jq` → `{"message":"dismissed"}`; confirm `status: "dismissed"` and that re-running `/api/engine/run` does not resurrect it as `suggested` again (dismissed findings persist their status).
- [ ] Run a finding with no `job_type` (e.g. the `nullsession:<ip>` informational one, `status: "done"` already) → `400` (`"finding has no runnable job"`).
- [ ] Unknown finding id → `404` on both `/run` and `/dismiss`.
- [ ] **UI**: War Table page (`WarTable.svelte`) — findings render as ranked cards with severity coloring; clicking "run" / "dismiss" round-trips through the same endpoints and updates live via the WS `finding` event.

---

## 14. OPSEC: quiet mode, jitter, scope-lock, lockout guard

- [ ] Scope-lock: already covered end-to-end in §10.
- [ ] Lockout guard: already covered end-to-end in §12 (`ad-spray`).
- [ ] Quiet mode + jitter: `curl -s -X POST $BASE/api/config -d '{"settings":{"opsec_quiet":true,"opsec_jitter_ms":3000}}' -H 'Content-Type: application/json' | jq` → `{"status":"success",...}`.
  - [ ] `curl -s $BASE/api/config | jq .settings` confirms both values stuck.
  - [ ] Run any NetExec-backed module (e.g. `ad-smb-enum`) and time it: `time curl -s -X POST $BASE/api/jobs -d '...'`. With quiet+jitter on, `run_tool` in `nxc_common.rs` sleeps a random `[0, opsec_jitter_ms)` delay before invoking the tool — expect visibly variable/added latency vs. `opsec_quiet:false` (jitter is skipped entirely when quiet mode is off).
  - [ ] Turn quiet mode back off (`opsec_quiet:false`) and confirm timing returns to normal (no artificial delay).
- [ ] `spray_lockout_buffer`: `curl -s -X POST $BASE/api/config -d '{"settings":{"spray_lockout_buffer":5}}' -H 'Content-Type: application/json' | jq`, then re-run the tight-lockout spray test from §12 — a threshold that previously passed (buffer 1) may now be refused (buffer 5 requires `threshold > 6`). Confirms the setting is live without a restart.
- [ ] Per-job override: pass `"lockout_buffer"` directly in an `ad-spray` job's `config` — overrides the global setting for just that job (check the refusal/accept threshold shifts accordingly).

---

## 15. Structured real-time events + native TUI

- [ ] With the server running, launch: `DECEBALUS_URL=http://localhost:8080 cargo run --features tui --bin decebalus-tui`.
- [ ] Confirm the TUI renders a findings list + hosts panel and the help line (`q quit · r refresh · e run engine · ⏎ run · d dismiss · ↑/↓ or j/k move`).
- [ ] Press `r` — refreshes from the live API (create a job from curl in another terminal first, confirm the TUI picks it up).
- [ ] Press `e` — triggers `/api/engine/run`; new findings (if any) appear.
- [ ] Navigate with `j`/`k` or arrows, press Enter on a runnable finding — confirm via `curl -s $BASE/api/jobs | jq` that a new job was created.
- [ ] Press `d` on a selected finding — confirm it's dismissed (same check as §13).
- [ ] Press `q` — exits cleanly, terminal restored (no leftover raw-mode garbling).
- [ ] With `DECEBALUS_TOKEN` set (§16) on the server but *not* exported for the TUI process — confirm the TUI's requests fail gracefully (not a panic) since it reads the same env var for its own bearer header.

---

## 16. Optional bearer auth

- [ ] Baseline (no `DECEBALUS_TOKEN` set): all endpoints work with no `Authorization` header, as used throughout this whole plan so far.
- [ ] Stop the server, restart with `DECEBALUS_TOKEN=supersecret cargo run`.
- [ ] `curl -s -o /dev/null -w '%{http_code}\n' $BASE/api/jobs` → `401`.
- [ ] `curl -s -H 'Authorization: Bearer supersecret' $BASE/api/jobs | jq` → `200`, normal response.
- [ ] `curl -s -H 'Authorization: Bearer wrongtoken' $BASE/api/jobs` → `401`.
- [ ] Frontend/War Table in a browser with the token set: confirm the UI itself breaks (no token stored by the SPA) unless you configure it to send the header — expected, this is a headless/CLI hardening feature per the code comment, not meant to gate the local web UI by default.
- [ ] Unset `DECEBALUS_TOKEN`, restart — auth gate disappears again (confirms it's fully opt-in, zero-config by default).

---

## 17. Secrets-at-rest encryption (dedicated pass)

- [ ] Delete/rename any existing `data/master.key` (back it up first if it protects real data!) and start the server fresh. Log line: `crypto: generated new master key at data/master.key`.
- [ ] `ls -la data/master.key` → permissions `-rw-------` (0600), owned by you.
- [ ] `cat data/master.key` — a 64-character hex string (32 bytes).
- [ ] Stop the server. Set `DECEBALUS_MASTER_KEY=<64-hex-chars-of-your-choice>` and restart — log line should **not** mention generating a new key (env var takes priority over the file). Add a credential (§10) and confirm `sqlite3 ... "select secret from credentials"` is ciphertext as before.
- [ ] **Wrong-key rejection**: stop the server, restart with a *different* `DECEBALUS_MASTER_KEY`, then `curl -s $BASE/api/credentials | jq` — the previously-added credential's `secret` field falls back to showing the raw (undecryptable) ciphertext string rather than crashing (per `credential_from_row`'s `unwrap_or` fallback) — confirms graceful degradation on key mismatch, not a 500 error.
- [ ] Restore the correct key (file or env var) — credentials decrypt correctly again.
- [ ] Loot ciphertext: already verified per-module in §7/§12. Cross-check once more: pick any file under `data/loot/`, confirm `xxd <file> | head -1` shows random-looking bytes (the 12-byte nonce) rather than a recognizable header/ASCII.
- [ ] `decebalus-backend loot decrypt <path-that-does-not-exist>` → clean error (`cannot read ...`), non-zero exit, no panic.
- [ ] `decebalus-backend loot decrypt <a-valid-loot-file>` with the **wrong** `DECEBALUS_MASTER_KEY` set → `decrypt failed` on stderr, non-zero exit — not garbage output.
- [ ] Cross-engagement isolation: create a second engagement, add a credential to it, confirm its loot lands under `data/loot/<second-engagement-id>/` (a different directory), and that `loot decrypt` against a path in the *first* engagement's directory using the correct master key still works (per-engagement keys are all derived from the one master key, so this should just work — the directory only matters for which derived key to apply).
- [ ] `cargo test crypto` — re-run the 5 crypto unit tests (`round_trips_a_string`, `wrong_engagement_fails_to_decrypt`, `same_plaintext_encrypts_differently_each_time`, `fingerprint_is_deterministic_and_engagement_scoped`, `round_trips_raw_bytes`) plus `cargo test --test loot_cli_tests` — all green.

---

## 18. Single-binary frontend embedding (dedicated pass)

- [ ] `decebalus-backend/scripts/build.sh --debug` — builds the frontend then the backend with `--features embed-ui`. Confirm both steps succeed and it prints the final binary path.
- [ ] Copy just the binary somewhere with **no** `decebalus-frontend/` nearby, e.g.:
  ```bash
  mkdir -p /tmp/decebalus-standalone && cd /tmp/decebalus-standalone
  cp /Users/narcis/programming/Decebalus/decebalus-backend/target/debug/decebalus-backend .
  ./decebalus-backend
  ```
  - [ ] `curl -sI http://localhost:8080/` → `200`, `Content-Type: text/html`.
  - [ ] `curl -s http://localhost:8080/ | grep -o '<title>[^<]*'` — real page title, not a 404.
  - [ ] `curl -sI http://localhost:8080/assets/index-<hash>.js` (get the real hashed filename from the page source) → `200`, correct JS `Content-Type`.
  - [ ] SPA deep-link fallback: `curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/some/deep/client/route` → `200` (serves `index.html`, not a 404) — the client-side router takes over from there.
  - [ ] A real 404 for a genuinely nonexistent asset path only matters if it collides with an API route — API routes (`/api/...`) still resolve normally; confirm `curl -s $BASE/api/modules | jq` still works from this standalone binary.
- [ ] **Staleness check** (the workflow question this feature raised): from the repo, edit something trivially visible in the frontend (e.go. change a label in `App.svelte` or `Navbar.svelte`), then run **only** `cargo build --features embed-ui` (skip `npm run build`) — confirm the *old* UI is what gets served (proves `build.rs`'s `rerun-if-changed` doesn't fabricate a rebuild when `dist/` didn't actually change, and that skipping the frontend build step really does leave you with stale content).
- [ ] Now run `npm run build` in `decebalus-frontend/`, then `cargo build --features embed-ui` again (no `scripts/build.sh` this time) — confirm Cargo *does* recompile (`Compiling decebalus-backend...` appears, not `Finished` instantly) and the new UI is served. This is the `build.rs` `rerun-if-changed` hook working correctly.
- [ ] Re-run `scripts/build.sh` (the intended one-command workflow) after another frontend edit — confirm it Just Works end to end.
- [ ] `cargo test --features embed-ui embedded_ui` — the `dist_output_is_embedded` sanity test passes.
- [ ] Confirm the **default** build (no `--features embed-ui`) is unaffected: `cargo build` then `cargo run` from the repo (with `decebalus-frontend/dist` present) still serves the UI from disk exactly as before, and `FRONTEND_DIR` still overrides the disk path.

---

## 19. Regression pass

- [ ] `cargo test` (default features) — full green run (unit + `job_executor_tests` + `loot_cli_tests` + `repository_tests` + `rule_engine_tests`).
- [ ] `cargo build` (default) — clean.
- [ ] `cargo build --features tui --bin decebalus-tui` — clean.
- [ ] `cargo build --features embed-ui` — clean (with `decebalus-frontend/dist` present).
- [ ] `cd ../decebalus-frontend && npm run check` — 0 errors, 0 warnings.
- [ ] `cargo run -- doctor` one more time — sanity check nothing regressed in tool detection.
- [ ] `git status` — review everything this test pass touched (new engagements/jobs/loot/master.key in `data/`, any frontend edits made for §18) before deciding what (if anything) to commit or clean up.

---

**Lab environment note (§11/§12):** for real AD coverage, stand up a small lab —
a Samba-AD container, a Windows Server + a couple of joined VMs, or a ready-made
kit like **DetectionLab** or **GOAD (Game of Active Directory)**. Everything in
this plan that doesn't need one focuses on plumbing (job validation, graceful
tool-missing errors, fact/finding persistence, loot encryption) — the actual AD
protocol behavior (NetExec/Certipy output parsing) already has automated
coverage listed inline in each section, so a lab is about confidence in the
*live* wiring, not filling a testing gap.
