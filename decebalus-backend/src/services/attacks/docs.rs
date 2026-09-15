//! Human-facing documentation for each module, kept deliberately separate from the
//! dispatch metadata in [`super::ModuleMeta`].
//!
//! `ModuleMeta` drives *behaviour* (dispatch, suggestions, the rule engine). This
//! module drives the *Modules page detail view*: a plain-language explanation of how
//! and why each module works, the representative underlying command, and the external
//! tools (with versions) it needs. Keeping it here means the wire response for
//! `GET /api/modules` can be rich without bloating every module's `meta()`.

use serde::Serialize;

/// An external tool a module shells out to, with a version hint and install command.
#[derive(Clone, Debug, Serialize, Default)]
pub struct ToolReq {
    pub name: String,
    /// The executable probed on `PATH` (e.g. "nxc").
    pub binary: String,
    /// Human version hint (e.g. "≥ 1.1"). Not enforced — guidance for the operator.
    pub version: String,
    pub install: String,
}

/// Rich, operator-facing documentation for a single module.
#[derive(Clone, Debug, Serialize, Default)]
pub struct ModuleDoc {
    pub how_it_works: String,
    pub why_it_works: String,
    /// A representative form of the underlying command (illustrative, not the exact
    /// argv — targets/creds are filled in at run time).
    pub example_command: String,
    pub requires_tools: Vec<ToolReq>,
    pub references: Vec<String>,
}

// ── Shared tool definitions ──────────────────────────────────────────────────

fn nxc() -> ToolReq {
    ToolReq {
        name: "NetExec".into(),
        binary: "nxc".into(),
        version: "≥ 1.1 (formerly CrackMapExec)".into(),
        install: "pipx install netexec".into(),
    }
}

fn smbclient() -> ToolReq {
    ToolReq {
        name: "Samba smbclient".into(),
        binary: "smbclient".into(),
        version: "Samba ≥ 4".into(),
        install: "apt install smbclient".into(),
    }
}

fn xfreerdp() -> ToolReq {
    ToolReq {
        name: "FreeRDP".into(),
        binary: "xfreerdp".into(),
        version: "FreeRDP 2.x or 3.x (xfreerdp / xfreerdp3)".into(),
        install: "apt install freerdp2-x11  (or freerdp3-x11)".into(),
    }
}

fn certipy() -> ToolReq {
    ToolReq {
        name: "Certipy".into(),
        binary: "certipy".into(),
        version: "certipy-ad ≥ 4.8".into(),
        install: "pipx install certipy-ad".into(),
    }
}

fn doc(
    how_it_works: &str,
    why_it_works: &str,
    example_command: &str,
    requires_tools: Vec<ToolReq>,
    references: &[&str],
) -> ModuleDoc {
    ModuleDoc {
        how_it_works: how_it_works.into(),
        why_it_works: why_it_works.into(),
        example_command: example_command.into(),
        requires_tools,
        references: references.iter().map(|s| s.to_string()).collect(),
    }
}

/// Documentation for a module by its `job_type`. Unknown types return an empty doc so
/// the endpoint stays total (a newly added module simply shows no extended detail
/// until an entry is added here).
pub fn module_doc(job_type: &str) -> ModuleDoc {
    match job_type {
        "ssh-brute" => doc(
            "Opens a TCP connection to the SSH service and tries each username × password pair \
             with an in-process SSH client (the russh crate), reading the server's authentication \
             result. Up to `concurrency` attempts run at once, and the job checks for cancellation \
             as it goes so it can be stopped mid-run.",
            "SSH password authentication returns a definitive success/failure per attempt, so any \
             account whose password is in your list is found. It works in practice because many \
             hosts — especially IoT and Raspberry Pi devices — keep weak or factory default \
             credentials and still allow password login.",
            "(built-in russh client)  ssh <user>@<target> -p 22",
            vec![],
            &[],
        ),

        "ftp-brute" => doc(
            "Connects to the FTP control port and sends USER/PASS for each pair over a raw TCP \
             socket, parsing the numeric reply code (230 = login OK).",
            "FTP sends credentials in cleartext and returns a clear per-attempt result. \
             Unauthenticated or weakly-protected FTP is still common on legacy and embedded devices, \
             and reused passwords make it a quick win.",
            "(built-in TCP client)  USER <user> / PASS <pass>",
            vec![],
            &[],
        ),

        "smb-brute" => doc(
            "Shells out to the system `smbclient`, attempting a session setup for each \
             username × password (optionally scoped to a domain). Success is read from smbclient's \
             exit status and output.",
            "SMB logons validate against local or domain accounts, so reused or weak Windows/Samba \
             passwords let you authenticate. Delegating to smbclient reuses a mature, well-tested \
             SMB stack instead of reimplementing the protocol.",
            "smbclient -L //<target> -U '<domain>\\<user>%<pass>'",
            vec![smbclient()],
            &[],
        ),

        "rdp-brute" => doc(
            "Shells out to FreeRDP (`xfreerdp`) and performs a full NLA / CredSSP handshake for \
             each credential; a clean handshake means the credentials are valid. It is the heaviest \
             brute module — every attempt is a subprocess plus a TLS handshake — so the default \
             concurrency is deliberately low.",
            "RDP with NLA authenticates the user before any session starts, giving a reliable \
             valid/invalid signal without opening a desktop. Internet- or LAN-exposed RDP with weak \
             passwords is one of the most common initial-access vectors.",
            "xfreerdp /v:<target> /u:<user> /p:<pass> /cert:ignore +auth-only",
            vec![xfreerdp()],
            &[],
        ),

        "file-steal" => doc(
            "Uses a built-in SFTP client (russh-sftp) to authenticate with a known credential and \
             download a single remote file. The retrieved file is stored encrypted at rest under \
             the engagement's loot directory.",
            "Once you hold valid SSH credentials, SFTP gives authenticated file read access over the \
             same channel. This demonstrates targeted post-exploitation exfiltration of a specific \
             file (e.g. /etc/passwd) rather than a broad sweep.",
            "(built-in SFTP client)  get <remote_path>",
            vec![],
            &[],
        ),

        "ad-smb-enum" => doc(
            "Runs `nxc smb <target>` and parses the banner for SMB signing, SMBv1 support, OS/build, \
             hostname and domain, recording each as a fact. Read-only: it does not attempt a login \
             beyond the protocol negotiation.",
            "SMB's protocol negotiation leaks host and domain metadata plus the signing posture \
             without any authentication. Signing status in particular decides whether an NTLM relay \
             attack is viable later.",
            "nxc smb <target>",
            vec![nxc()],
            &["https://www.netexec.wiki/"],
        ),

        "ad-null-session" => doc(
            "Attempts an anonymous (null) SMB session — `nxc smb <target> -u '' -p ''` — and, where \
             the server allows it, enumerates domain users and shares.",
            "Misconfigured domain controllers and file servers still permit anonymous SMB, which \
             exposes the full user list (ideal fuel for a later password spray) and open shares — \
             all without a single credential.",
            "nxc smb <target> -u '' -p '' --users --shares",
            vec![nxc()],
            &["https://www.netexec.wiki/"],
        ),

        "ad-password-policy" => doc(
            "Runs `nxc smb <target> --pass-pol` and parses the account-lockout threshold, observation \
             window and minimum password length into facts.",
            "Knowing the lockout threshold and window is exactly what makes safe password spraying \
             possible: the spray module reads these facts to stay under the limit. Quiet and \
             read-only, so it is a natural first step before any guessing.",
            "nxc smb <target> --pass-pol",
            vec![nxc()],
            &["https://www.netexec.wiki/"],
        ),

        "ad-share-hunt" => doc(
            "With a valid credential, runs `nxc smb <target> --shares`, lists the shares readable by \
             that account and flags high-interest names (e.g. SYSVOL, backups, IT, profiles).",
            "Authenticated domain users can frequently read shares holding logon scripts, configs and \
             plaintext or reversibly-stored credentials. Surfacing readable shares points you \
             straight at where sensitive data is likely to live. Read-only.",
            "nxc smb <target> -u <user> -p <pass> --shares",
            vec![nxc()],
            &["https://www.netexec.wiki/"],
        ),

        "ad-cred-validate" => doc(
            "Authenticates a credential over SMB with `nxc smb` — either a password or an NT hash — \
             and reports whether it is valid and whether it grants local admin (NetExec's `Pwn3d!` \
             marker).",
            "It confirms that a captured or guessed credential actually works before you build on it, \
             and instantly reveals admin access. Because NetExec accepts an NT hash (`-H`), it also \
             validates pass-the-hash material, not just cleartext passwords.",
            "nxc smb <target> -u <user> -p <pass>       (or: -H <nthash>)",
            vec![nxc()],
            &["https://www.netexec.wiki/"],
        ),

        "ad-spray" => doc(
            "Sprays a single password across many users via `nxc smb`, but first consults the recorded \
             password policy and paces itself to stay under the lockout threshold (override with \
             `force`). Confirmed logons are stored as credentials.",
            "One common password (e.g. Season+Year) very often works for at least one account across a \
             large user set. Trying one password at a time — instead of many passwords per user — \
             avoids the account lockouts that ordinary brute force would trigger.",
            "nxc smb <target> -u users.txt -p '<password>' --continue-on-success",
            vec![nxc()],
            &["https://www.netexec.wiki/", "https://www.thehacker.recipes/ad/movement/credentials/spraying"],
        ),

        "ad-kerberoast" => doc(
            "With a valid domain credential, runs `nxc ldap <target> --kerberoasting` to request TGS \
             service tickets for accounts that have an SPN, saves the crackable hashes, and emits a \
             ready-to-run hashcat command (mode 13100).",
            "Any authenticated user is allowed to request a service ticket, and that ticket is \
             encrypted with the service account's password hash. Weak service-account passwords \
             therefore crack offline, with no further interaction with the domain — a classic \
             low-noise privilege path.",
            "nxc ldap <target> -u <user> -p <pass> --kerberoasting out.txt   →   hashcat -m 13100",
            vec![nxc()],
            &["https://www.thehacker.recipes/ad/movement/kerberos/kerberoast", "hashcat mode 13100"],
        ),

        "ad-asrep" => doc(
            "Runs `nxc ldap <target> --asreproast` to collect AS-REP material for accounts that have \
             Kerberos pre-authentication disabled, and emits a hashcat command (mode 18200).",
            "When 'Do not require Kerberos pre-authentication' is set on an account, the KDC will \
             return an AS-REP encrypted with that user's key to anyone who asks. That response is \
             crackable offline, so a single misconfigured account yields a password with no prior \
             access to it.",
            "nxc ldap <target> -u <user> -p <pass> --asreproast out.txt   →   hashcat -m 18200",
            vec![nxc()],
            &["https://www.thehacker.recipes/ad/movement/kerberos/asreproast", "hashcat mode 18200"],
        ),

        "ad-adcs" => doc(
            "Runs `certipy find -vulnerable -stdout` to enumerate AD Certificate Services templates \
             and flags ESC1–ESC8 misconfigurations, then emits an example `certipy req` command for \
             the exploitable template.",
            "A vulnerable certificate template can let a low-privileged user request a certificate \
             that authenticates *as* a privileged account (e.g. Domain Admin) — a reliable domain \
             takeover. Certipy automates both finding these templates and abusing them.",
            "certipy find -u <user>@<domain> -p <pass> -dc-ip <target> -vulnerable -stdout",
            vec![certipy()],
            &["https://github.com/ly4k/Certipy", "https://www.thehacker.recipes/ad/movement/adcs"],
        ),

        "ad-relay-recon" => doc(
            "Detection only. Reads the SMB-signing facts already gathered by the enumeration modules, \
             lists the hosts with signing disabled, and prints the exact ntlmrelayx / Responder \
             commands to run against them. It never sends traffic itself.",
            "NTLM relay only works against hosts that do not require SMB signing. Pre-computing the \
             signing-disabled target list and the commands lets you decide whether to run a relay \
             out-of-band, keeping this step quiet and read-only.",
            "(advisory)  ntlmrelayx.py -tf targets.txt -smb2support   +   responder -I <iface>",
            vec![],
            &["https://www.thehacker.recipes/ad/movement/ntlm/relay"],
        ),

        "ad-bloodhound" => doc(
            "With a domain credential, runs `nxc ldap <target> --bloodhound --collection All` to \
             collect users, groups, sessions, ACLs and trusts into a BloodHound-ready dataset, \
             stored as loot (a zip).",
            "BloodHound turns raw Active Directory relationships into concrete attack paths — for \
             example, who can ultimately reach Domain Admin. Collection is just authenticated LDAP \
             and SMB reads that any domain user is permitted to perform.",
            "nxc ldap <target> -u <user> -p <pass> --bloodhound --collection All --dns-server <dc-ip>",
            vec![nxc(), ToolReq {
                name: "BloodHound (to view results)".into(),
                binary: "bloodhound".into(),
                version: "BloodHound CE / 4.x — optional, for analysis".into(),
                install: "https://bloodhound.specterops.io/".into(),
            }],
            &["https://bloodhound.specterops.io/"],
        ),

        _ => ModuleDoc::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_module_has_documentation() {
        // A module without a doc entry returns the empty default; require that every
        // registered job_type has real how/why text so the Modules page never shows a
        // blank detail panel.
        for meta in crate::services::attacks::all_meta() {
            let d = module_doc(&meta.job_type);
            assert!(
                !d.how_it_works.is_empty() && !d.why_it_works.is_empty(),
                "module '{}' is missing documentation in docs.rs",
                meta.job_type
            );
        }
    }
}
