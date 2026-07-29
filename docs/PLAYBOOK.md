# The Decebalus Assumed-Breach Playbook

This documents the canonical opening sequence Decebalus encodes, and how the
next-move rule engine (`decebalus-backend/src/services/rules.rs`) turns observed
**facts** into ranked **findings**. Everything is deterministic and scope-locked.

## Model

- **Engagement** — a named scope (CIDRs) + optional AD context (domain, DC) + an
  optional starting credential. Anchors scope-lock and owns all state.
- **Facts** — observations about a subject (`host` / `domain`): `smb_signing`,
  `null_session`, `users`, `readable_shares`, `lockout_threshold`, `roastable_spns`,
  `adcs_present`, … Written by modules, read by the rule engine.
- **Credentials** — the shared credential store; validated creds unlock the
  credentialed playbook.
- **Findings** — ranked next-moves with a value score, a copy-paste command, and
  (when safe) a one-click job. `read_only` moves auto-run; `risky` moves wait for
  the operator (suggest-first).

## The opening loop

| Step | Module (job type) | Safety | Produces |
|------|-------------------|--------|----------|
| Host discovery | `discovery`, `port-scan`, `nmap-scan` | read-only | hosts, ports, OS |
| SMB enumeration | `ad-smb-enum` | read-only | `smb_signing`, `smbv1`, `os`, `domain` |
| Null-session | `ad-null-session` | read-only | `null_session`, `users`, `shares` |
| Password policy | `ad-password-policy` | read-only | `lockout_threshold`, `min_pw_length` |
| Share hunt | `ad-share-hunt` | read-only | `readable_shares`, `interesting_shares` |
| Relay recon | `ad-relay-recon` | read-only | relay-target finding (detection only) |
| Credential spray | `ad-spray` | risky | validated `credentials` (lockout-aware) |
| Validate credential | `ad-cred-validate` | risky | `valid_cred`, privilege |
| Kerberoast / AS-REP | `ad-kerberoast`, `ad-asrep` | risky | hashes + hashcat command |
| ADCS (Certipy) | `ad-adcs` | risky | ESC1–ESC8 findings |
| BloodHound | `ad-bloodhound` | risky | collection zip |

## Rules (fact → next move)

1. **Open SMB, no signing fact** → auto-run `ad-smb-enum`.
2. **Open SMB, not checked anonymously** → auto-run `ad-null-session`.
3. **`smb_signing = false`** → relay opportunity (auto `ad-relay-recon`, value 66).
4. **`null_session = true`** → notable finding; enables spraying.
5. **Readable SYSVOL/NETLOGON** → GPP password hunt (risky, value 60).
6. **`users` known, no validated cred** → suggest `ad-spray` (value 58).
7. **Validated cred + domain/DC** → unlock Kerberoast (74), AS-REP (70),
   ADCS (80), BloodHound (52) — each prefilled with the credential.
8. **Admin/DA cred** → headline finding (value 95) + secretsdump suggestion.

## OPSEC guarantees

- **Scope-lock** — modules refuse any target outside the engagement's CIDRs.
- **Lockout guard** — spraying consults the discovered lockout policy and refuses
  when a single attempt is unsafe (override with `force`).
- **Quiet mode** — `opsec_quiet` adds jitter and prefers stealthier options.
- **Suggest-first** — risky moves never auto-run; they wait for the operator.
