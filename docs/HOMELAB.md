# Decebalus Homelab — Building a Safe Target Range

This is a from-scratch guide to standing up a home lab that exercises every
Decebalus module honestly: network discovery, legacy service brute-forcing
(§7 of `TEST_PLAN.md`), and the full assumed-breach AD chain (§11–§13 —
SMB enum, null sessions, password spray, Kerberoasting, AS-REP roasting,
ADCS, relay recon, BloodHound). `TEST_PLAN.md` explicitly says this
coverage "can't be honestly verified" without a real domain — this doc is
that domain.

**Design goal:** everything vulnerable lives inside virtual machines on your
Linux box, on a network segment that has no path to your home LAN or to your
personal Windows/MacBook hardware. Your MacBook and Windows machine are never
required, never joined to the lab domain, and never run attack traffic. If
something in the lab gets popped (it's supposed to), the blast radius stops
at a VM snapshot.

---

## 1. What you're building

```
┌─────────────────────────────────────────────────────────────────────┐
│  Linux host ("hypervisor box")                                      │
│                                                                       │
│   Isolated virtual network — e.g. 192.168.56.0/24                    │
│   (VirtualBox "Host-only"/"Internal Network" — NOT bridged to Wi-Fi) │
│                                                                       │
│   ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐ │
│   │ Attacker VM│   │  DC01      │   │  SRV/WKS01 │   │ legacy-svcs│ │
│   │ (Debian)   │   │ (Win Srv)  │   │ (Win 10/   │   │ (Docker:   │ │
│   │ Decebalus  │   │ Domain     │   │  Srv2, GOAD│   │  ssh/ftp/  │ │
│   │ + nxc,     │   │ Controller │   │  member)   │   │  smb/rdp   │ │
│   │ certipy,   │   │            │   │            │   │  targets)  │ │
│   │ impacket…  │   │            │   │            │   │            │ │
│   └────────────┘   └────────────┘   └────────────┘   └────────────┘ │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
        ▲
        │ SSH/RDP over an isolated hop only — never joined to the domain
   (optional) MacBook / Windows box used purely as a remote viewer
```

Everything that's a legitimate attack target (the domain, the legacy
services) is a VM or container on the Linux host. The only thing that ever
leaves that segment is you, looking at a screen.

---

## 2. Hardware & lab-size decision

Check what the primary Linux machine actually has before picking a topology:

```bash
free -h        # RAM
nproc          # CPU cores
df -h /        # free disk (you'll want 100GB+ free for GOAD)
```

Three topology tiers, using [GOAD](https://github.com/Orange-Cyberdefense/GOAD)
(Game of Active Directory — the exact kit `TEST_PLAN.md` calls out):

| Lab | VMs | Domains | RAM needed | Best for |
|---|---|---|---|---|
| **MINILAB** | 2 (1 DC + 1 workstation) | 1 | ~8–10 GB | Modest hardware, first pass at §11/§12 |
| **GOAD-Light** | 3 | 1 forest | **20 GB min** | Recommended default — full attack chain, single forest |
| **GOAD** (full) | 5 | 2 forests (cross-trust) | **24 GB min** | Cross-forest/trust attacks, relay across domains |
| **Disk (any tier)** | — | — | ~115 GB total, more with snapshots | |

Start with **GOAD-Light** if the host has ≥24GB RAM free for VMs (leaving
headroom for the host OS + attacker VM + Docker targets on top). Drop to
**MINILAB** if RAM is tighter — it still gives you a real DC + joined
workstation, which is enough for SMB enum, null sessions, password policy,
spraying, Kerberoasting, and AS-REP roasting. It just won't have the
second/third machine GOAD-Light adds for share-hunting variety and
ADCS/ESC template richness.

If neither tier fits comfortably, that's a sign to do this on the Linux
machine alone and skip pulling in the second Linux box for now — an
overcommitted hypervisor host produces flaky VMs, which reads as false
negatives when you're trying to validate Decebalus's parsing logic.

---

## 3. Step 1 — Prep the Linux host

Install VirtualBox + Vagrant (the officially supported, most-documented path
for GOAD on Linux) and an isolated host-only network:

```bash
sudo apt update
sudo apt install -y virtualbox python3.10-venv sshpass lftp rsync openssh-client
# Install Vagrant from https://developer.hashicorp.com/vagrant/install#linux
vagrant plugin install vagrant-reload vagrant-vbguest winrm winrm-fs winrm-elevated
```

VirtualBox's default "Host-only" network (e.g. `vboxnet0`, `192.168.56.0/24`)
is already isolated from your Wi-Fi/Ethernet adapter by default — it's a
virtual switch VirtualBox creates with no bridge to your physical NIC. Verify
this stays true rather than assuming it:

```bash
VBoxManage list hostonlyifs
```

**Do not** change any lab VM's or the attacker VM's network adapter to
"Bridged" — bridged mode puts the VM directly on your home LAN with its own
IP, which is exactly the exposure you're trying to avoid. Host-only or
Internal Network only.

---

## 4. Step 2 — Deploy the AD domain with GOAD

```bash
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD
./goad.sh
```

At the interactive prompt:

```
...>set_lab GOAD-Light
...>set_provider virtualbox
...>install
```

(swap `GOAD-Light` for `MINILAB` per your sizing decision above). This takes
a while — it provisions VMs via Vagrant then configures the domain,
intentional misconfigurations, and vulnerable ADCS templates via Ansible.
Grab coffee.

Windows evaluation media: GOAD's Vagrant boxes pull pre-built Windows
Server/10 images, so you don't need to source your own ISO or license — this
is the point of using GOAD rather than hand-rolling a DC.

When `install` finishes, note down the DC's IP and the domain name/admin
creds GOAD prints (or check `GOAD/ansible/inventory/...` for the lab you
picked) — you'll feed these into a Decebalus engagement in Step 5.

**Snapshot immediately** once the install completes and before you run any
attacks against it:

```bash
cd GOAD/vagrant/<your-lab>
vagrant snapshot save all clean-install
```

To reset after a messy run (e.g. a lockout from spraying, or ADCS enrollment
side effects):

```bash
vagrant snapshot restore all clean-install
```

---

## 5. Step 3 — Legacy-protocol targets (for §7 of the test plan)

The SSH/FTP/SMB/RDP brute-force and file-steal modules don't need a domain —
just a throwaway service with a known weak credential. Run these as
containers on the same host, attached to the same isolated network (or a
separate Docker bridge network — Docker's default bridge is already
host-only unless you explicitly publish ports to `0.0.0.0`):

```bash
# SSH target with a deliberately weak password
docker run -d --name lab-ssh -p 2222:22 \
  -e PASSWORD_ACCESS=true -e USER_NAME=labuser -e USER_PASSWORD=labpass123 \
  linuxserver/openssh-server

# FTP target
docker run -d --name lab-ftp -p 2121:21 -p 30000-30009:30000-30009 \
  -e USERS="labuser|labpass123" \
  delfer/alpine-ftp-server

# Plain Samba share (SMB brute-force target)
docker run -d --name lab-smb -p 445:445 \
  -e USERNAME=labuser -e PASSWORD=labpass123 -e SHARE=loot \
  dperson/samba -s "loot;/share;yes;no;no;labuser"
```

Only bind these to the isolated network's interface, not `0.0.0.0` on your
main NIC — pass `-p 192.168.56.X:2222:22` (the isolated network's address)
rather than a bare `-p 2222:22` if the host has more than one active
interface, so the service isn't reachable from your home LAN at all.

For RDP, it's easier to just point `rdp-brute` at one of the GOAD Windows
VMs (with RDP enabled and a known weak local account) rather than finding a
container RDP target.

---

## 6. Step 4 — The attacker box (runs Decebalus)

Create a Debian/Ubuntu VM on the *same* isolated network as the GOAD VMs and
Docker targets — this is the box that actually runs Decebalus and needs line
of sight to the lab. Keeping it as its own VM (rather than running Decebalus
directly on your host) means you can snapshot it too, and it mirrors how
`install.sh` already expects to be used ("Intended for a Kali/Debian attack
box").

Inside that VM:

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# External tooling Decebalus's AD modules shell out to
sudo apt install -y nmap smbclient
pipx install netexec        # provides `nxc`
pipx install certipy-ad
pipx install impacket        # ntlmrelayx.py, secretsdump.py
pipx install bloodhound       # bloodhound-python
sudo apt install -y freerdp2-x11 hashcat

git clone <your Decebalus repo> && cd Decebalus
./install.sh
cd decebalus-backend && cargo run -- doctor
```

`doctor` should now show ✓ for everything relevant to the modules you plan
to test — confirm this before moving on, it's the fastest way to catch a
missing tool before it shows up as a confusing job failure later.

Snapshot this VM once `doctor` is clean, same as the GOAD VMs.

---

## 7. Step 5 — Point Decebalus at the lab and smoke-test

From the attacker VM, create an engagement scoped **only** to the lab's
isolated subnet — this is the scope-lock feature from `PLAYBOOK.md` doing
real work here, not just a formality:

```bash
export BASE=http://localhost:8080
curl -s -X POST $BASE/api/engagements -d '{
  "name": "goad-lab",
  "scope_cidrs": ["192.168.56.0/24"],
  "domain": "<goad-domain>",
  "dc_ip": "<dc-ip-from-goad-install>",
  "username": "<a starting low-priv GOAD user>",
  "password": "<its password>"
}' -H 'Content-Type: application/json' | jq
```

Because `scope_cidrs` is locked to the lab subnet, any accidental typo that
points a job outside the lab (or at your real home LAN) gets refused rather
than actually run — worth deliberately testing once:

```bash
curl -s -X POST $BASE/api/jobs -d '{"job_type":"port-scan","target":"8.8.8.8"}' \
  -H 'Content-Type: application/json' | jq
# expect: job created, then status "failed", results "Refused: target 8.8.8.8 is outside the engagement scope"
```

Then run `TEST_PLAN.md` §2 (discovery/port-scan) against `192.168.56.0/24`,
§7 against the Docker targets, and §11–§13 against the GOAD DC — that's the
whole "assumed-breach opening loop" from `PLAYBOOK.md` exercised against a
real domain.

---

## 8. Optional: bringing in the other machines

You listed a second Linux box, a Windows machine, and a MacBook as available
if needed. None are required — GOAD + Docker targets on the primary Linux
host cover every module. If you still want to use them:

- **Second Linux machine** — lowest-risk addition. Use it to host the Docker
  legacy-protocol targets (Step 5) instead of the primary box, freeing more
  RAM there for GOAD VMs. Keep it on the same isolated segment (a second NIC
  into the host-only network, or a dedicated switch/VLAN) — not your regular
  home LAN.
- **Windows machine** — don't join your real Windows install to the GOAD
  domain or run lab services on it directly; GOAD/MINILAB already provides
  Windows Server + Windows 10 VMs for that purpose. If you want a "physical"
  Windows target instead of a VM, install Windows in a VM *on the Linux
  hypervisor* rather than repurposing your personal machine — same isolation
  guarantees, no risk to your real OS install. The only safe use of the
  physical Windows box is as a remote viewer: RDP/browser into the lab
  network over an SSH tunnel, never bridged onto the isolated segment
  itself.
- **MacBook** — same principle, and macOS isn't a realistic AD domain member
  anyway. Use it only to open the War Table UI (`http://<attacker-vm-ip>:8080`)
  or SSH into the attacker VM, via an SSH tunnel or a second, non-bridged
  network adapter — never give it a routable address on the lab subnet, and
  never run Decebalus jobs from it directly.

If you do add a second box on the isolated segment, double-check it can't
route back out to your home LAN (i.e. it's single-homed to the lab network,
or has IP forwarding disabled) — the whole point of the isolated segment
collapses if one machine bridges both networks.

---

## 9. Safety & reset checklist

- [ ] Lab VMs and Docker targets are on an isolated/host-only network with
      **no bridged adapter** to your home Wi-Fi/Ethernet.
- [ ] `scope_cidrs` on every Decebalus engagement matches the lab subnet only
      — never your home LAN's range.
- [ ] GOAD/MINILAB creds are the lab's intentionally-weak defaults — don't
      reuse any of your real passwords when setting them up.
- [ ] Snapshots taken right after GOAD install and right after the attacker
      VM's `doctor` check passes clean — `vagrant snapshot restore all
      clean-install` gets you back to a known-good state after a lockout,
      a botched ADCS enrollment, or anything else messy.
- [ ] Personal Windows machine and MacBook are never joined to the lab
      domain and never run attack traffic — viewer-only, over a tunnel.
- [ ] This is your own hardware for your own training — keep it that way;
      don't expose the lab network, the attacker VM, or the War Table UI to
      the internet.

---

## 10. Module → lab-feature mapping

Quick reference for which lab piece exercises which Decebalus capability:

| Decebalus module(s) | Needs |
|---|---|
| `discovery`, `port-scan`, `nmap-scan` | Any VM/container on the lab subnet |
| `ssh-brute`, `ftp-brute`, `smb-brute`, `file-steal` | Docker legacy-service targets (§5) |
| `rdp-brute` | A GOAD Windows VM with RDP + a weak local account |
| `ad-smb-enum`, `ad-null-session`, `ad-password-policy`, `ad-share-hunt` | GOAD DC (read-only, no creds needed for most) |
| `ad-spray`, `ad-cred-validate` | GOAD DC + the `users` fact from null-session/enum |
| `ad-kerberoast`, `ad-asrep` | GOAD DC with SPN-bearing / no-preauth accounts (GOAD ships these by design) |
| `ad-adcs` | GOAD's vulnerable ADCS templates (ESC1–ESC8 depending on lab version) |
| `ad-relay-recon` | A GOAD host with SMB signing disabled (GOAD ships at least one) |
| `ad-bloodhound` | GOAD DC + a validated credential |
| Scope-lock, lockout guard, quiet/jitter (OPSEC) | Any of the above — test by deliberately tripping them (Step 6) |

---

## Sources

- [GOAD repository](https://github.com/Orange-Cyberdefense/GOAD)
- [GOAD Linux installation guide](https://orange-cyberdefense.github.io/GOAD/installation/linux/)
- [GOAD installation overview / providers](https://orange-cyberdefense.github.io/GOAD/installation/)
