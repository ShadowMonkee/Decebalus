<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { getHosts, getJobs, createAttackJob, cancelJob, type Host, type Job } from '../api';
  import { wsMessages } from '../stores/websocketStore';

  type AttackType = 'ssh-brute' | 'ftp-brute' | 'smb-brute' | 'rdp-brute' | 'file-steal';

  const DEFAULT_PORTS: Record<AttackType, number> = {
    'ssh-brute': 22,
    'ftp-brute': 21,
    'smb-brute': 445,
    'rdp-brute': 3389,
    'file-steal': 22,
  };

  let hosts: Host[] = [];
  let jobs: Job[] = [];
  let loading = false;
  let launchError = '';
  let scanProgress: Map<string, string> = new Map();

  // Form state
  let attackType: AttackType = 'ssh-brute';
  let target = '';
  let port = '';
  let concurrency = '3';
  let usernames = '';
  let passwords = '';
  let domain = '';
  let username = '';
  let password = '';
  let remotePath = '/etc/passwd';

  $: isBrute = attackType !== 'file-steal';
  $: usesDomain = attackType === 'smb-brute' || attackType === 'rdp-brute';

  $: upHosts = hosts.filter(h => h.status === 'Up');
  $: attackJobs = jobs.filter(j => ['ssh-brute', 'ftp-brute', 'smb-brute', 'rdp-brute', 'file-steal'].includes(j.job_type));
  $: runningAttacks = attackJobs.filter(j => j.status === 'running' || j.status === 'queued');
  $: doneAttacks = attackJobs.filter(j => j.status === 'completed' || j.status === 'failed' || j.status === 'cancelled');

  async function refresh() {
    [hosts, jobs] = await Promise.all([getHosts(), getJobs()]);
  }

  async function launch() {
    launchError = '';
    if (!target) { launchError = 'Select a target host.'; return; }

    const config: Record<string, unknown> = { target };

    if (isBrute) {
      config.port = port ? parseInt(port) : DEFAULT_PORTS[attackType];
      config.concurrency = parseInt(concurrency) || 3;
      const userList = usernames.trim().split('\n').map(s => s.trim()).filter(Boolean);
      const passList = passwords.trim().split('\n').map(s => s.trim()).filter(Boolean);
      if (userList.length) config.usernames = userList;
      if (passList.length) config.passwords = passList;
      if (usesDomain && domain.trim()) config.domain = domain.trim();
    } else {
      if (!username) { launchError = 'Username is required.'; return; }
      if (!password) { launchError = 'Password is required.'; return; }
      if (!remotePath) { launchError = 'Remote path is required.'; return; }
      const portNum = port ? parseInt(port) : 22;
      config.port = portNum;
      config.username = username;
      config.password = password;
      config.remote_path = remotePath;
    }

    loading = true;
    try {
      await createAttackJob(attackType, config);
      await refresh();
    } catch (e: any) {
      launchError = e.message ?? 'Launch failed';
    } finally {
      loading = false;
    }
  }

  async function handleCancel(id: string) {
    try { await cancelJob(id); await refresh(); } catch {}
  }

  function parseResult(job: Job): any {
    if (!job.results) return null;
    try { return JSON.parse(job.results); } catch { return null; }
  }

  let unsubscribe: (() => void) | null = null;

  onMount(async () => {
    await refresh();

    unsubscribe = wsMessages.subscribe((raw: unknown) => {
      if (!raw || typeof raw !== 'string') return;
      const msg = raw;
      if (msg.startsWith('scan_progress:')) {
        const rest = msg.slice('scan_progress:'.length);
        const idx = rest.indexOf(':');
        if (idx !== -1) {
          const jobId = rest.slice(0, idx);
          const text = rest.slice(idx + 1);
          scanProgress = new Map(scanProgress).set(jobId, text);
        }
      }
      if (msg.startsWith('job_completed:') || msg.startsWith('job_failed:') || msg.startsWith('job_cancelled:') || msg.startsWith('job_running:')) {
        refresh();
      }
    });
  });

  onDestroy(() => { if (unsubscribe) unsubscribe(); });
</script>

<div class="attacks-page">
  <div class="page-header">
    <h1>Attack Modules</h1>
    <p>Launch attacks against discovered targets. Authorized use only.</p>
  </div>

  <div class="attacks-layout">
    <!-- Launch panel -->
    <section class="card launch-panel">
      <h2>Configure Attack</h2>

      <div class="type-tabs">
        <button class:active={attackType === 'ssh-brute'} on:click={() => attackType = 'ssh-brute'}>SSH Brute</button>
        <button class:active={attackType === 'ftp-brute'} on:click={() => attackType = 'ftp-brute'}>FTP Brute</button>
        <button class:active={attackType === 'smb-brute'} on:click={() => attackType = 'smb-brute'}>SMB Brute</button>
        <button class:active={attackType === 'rdp-brute'} on:click={() => attackType = 'rdp-brute'}>RDP Brute</button>
        <button class:active={attackType === 'file-steal'} on:click={() => attackType = 'file-steal'}>File Steal</button>
      </div>

      <div class="form-group">
        <label for="target-select">Target host</label>
        <select id="target-select" bind:value={target}>
          <option value="">-- select a host --</option>
          {#each upHosts as h}
            <option value={h.ip}>{h.ip}{h.hostname ? ` (${h.hostname})` : ''}</option>
          {/each}
        </select>
        {#if upHosts.length === 0}
          <small class="hint">No hosts with status Up. Run a discovery scan first.</small>
        {/if}
      </div>

      <div class="form-group">
        <label for="port-input">Port <small>(leave blank for default)</small></label>
        <input id="port-input" type="number" bind:value={port}
          placeholder={String(DEFAULT_PORTS[attackType])} />
      </div>

      {#if isBrute}
        {#if usesDomain}
          <div class="form-group">
            <label for="domain-input">Domain <small>(optional)</small></label>
            <input id="domain-input" type="text" bind:value={domain} placeholder="WORKGROUP" />
          </div>
        {/if}
        <div class="form-group">
          <label for="concurrency-input">Concurrency</label>
          <input id="concurrency-input" type="number" bind:value={concurrency} min="1" max="20" />
        </div>
        <div class="form-group">
          <label for="usernames-input">Usernames <small>(one per line, blank = built-in defaults)</small></label>
          <textarea id="usernames-input" bind:value={usernames} rows="4"
            placeholder="root&#10;pi&#10;admin"></textarea>
        </div>
        <div class="form-group">
          <label for="passwords-input">Passwords <small>(one per line, blank = built-in defaults)</small></label>
          <textarea id="passwords-input" bind:value={passwords} rows="4"
            placeholder="raspberry&#10;admin&#10;password"></textarea>
        </div>
      {:else}
        <div class="form-group">
          <label for="username-input">Username</label>
          <input id="username-input" type="text" bind:value={username} placeholder="pi" />
        </div>
        <div class="form-group">
          <label for="password-input">Password</label>
          <input id="password-input" type="text" bind:value={password} placeholder="raspberry" />
        </div>
        <div class="form-group">
          <label for="remote-path-input">Remote path</label>
          <input id="remote-path-input" type="text" bind:value={remotePath} placeholder="/etc/passwd" />
        </div>
      {/if}

      {#if launchError}
        <p class="error-msg">{launchError}</p>
      {/if}

      <button class="btn-primary launch-btn" on:click={launch} disabled={loading}>
        {loading ? 'Launching…' : 'Launch'}
      </button>
    </section>

    <!-- Running / queued -->
    {#if runningAttacks.length > 0}
      <section class="card">
        <h2>Running</h2>
        <div class="attack-list">
          {#each runningAttacks as job}
            <div class="attack-item">
              <div class="attack-header">
                <span class="attack-type">{job.job_type}</span>
                <span class="attack-target">{job.config?.target ?? ''}</span>
                <span class="badge-info">{job.status}</span>
                <button class="btn-danger btn-sm" on:click={() => handleCancel(job.id)}>Cancel</button>
              </div>
              {#if scanProgress.has(job.id)}
                <div class="progress-line">{scanProgress.get(job.id)}</div>
              {/if}
            </div>
          {/each}
        </div>
      </section>
    {/if}

    <!-- Completed -->
    {#if doneAttacks.length > 0}
      <section class="card">
        <h2>Completed</h2>
        <div class="attack-list">
          {#each doneAttacks as job}
            {@const result = parseResult(job)}
            <div class="attack-item done">
              <div class="attack-header">
                <span class="attack-type">{job.job_type}</span>
                <span class="attack-target">{job.config?.target ?? ''}</span>
                <span class="badge-{job.status === 'completed' ? 'success' : 'danger'}">{job.status}</span>
              </div>

              {#if result}
                {#if job.job_type === 'file-steal'}
                  <div class="result-block">
                    <div class="result-meta">
                      <span>Remote: <code>{result.remote_path}</code></span>
                      <span>Saved: <code>{result.local_path}</code></span>
                      <span>{result.size_bytes} bytes</span>
                    </div>
                    {#if result.preview}
                      <pre class="file-preview">{result.preview}</pre>
                    {/if}
                  </div>
                {:else}
                  <div class="result-block">
                    <div class="result-meta">
                      <span>{result.attempts ?? 0} attempts</span>
                    </div>
                    {#if result.found && result.found.length > 0}
                      <div class="creds-found">
                        <strong>Found credentials:</strong>
                        <ul>
                          {#each result.found as cred}
                            <li><code>{cred}</code></li>
                          {/each}
                        </ul>
                      </div>
                    {:else}
                      <p class="no-creds">No credentials found.</p>
                    {/if}
                  </div>
                {/if}
              {:else if job.status === 'failed'}
                <p class="error-msg">{job.results ?? 'Job failed'}</p>
              {/if}
            </div>
          {/each}
        </div>
      </section>
    {/if}
  </div>

  <div class="card disclaimer">
    <strong>Authorized use only.</strong> These modules are for penetration testing on systems you own or have explicit written permission to test. Unauthorized access is illegal.
  </div>
</div>

<style>
  .attacks-page { display: flex; flex-direction: column; gap: 1.5rem; }

  .page-header h1 { font-size: 1.75rem; font-weight: 700; color: var(--bronze); }
  .page-header p  { color: var(--ash); margin-top: 0.25rem; font-size: 0.9rem; }

  .attacks-layout { display: flex; flex-direction: column; gap: 1.5rem; }

  .launch-panel h2, section.card h2 {
    font-size: 1.1rem; font-weight: 600; color: var(--ash-light);
    margin-bottom: 1rem;
  }

  .type-tabs { display: flex; gap: 0.5rem; margin-bottom: 1.25rem; flex-wrap: wrap; }
  .type-tabs button {
    padding: 0.35rem 0.85rem; border-radius: 4px; border: 1px solid var(--ash);
    background: transparent; color: var(--ash); cursor: pointer; font-size: 0.85rem;
    transition: background 0.15s, color 0.15s;
  }
  .type-tabs button.active {
    background: var(--bronze); color: #000; border-color: var(--bronze); font-weight: 600;
  }

  .form-group { display: flex; flex-direction: column; gap: 0.3rem; margin-bottom: 0.9rem; }
  .form-group label { font-size: 0.85rem; color: var(--ash-light); }
  .form-group label small { color: var(--ash); font-weight: normal; }
  .form-group input, .form-group select, .form-group textarea {
    background: var(--forest-dark, #1a1a1a); border: 1px solid #444; border-radius: 4px;
    color: var(--ash-light); padding: 0.4rem 0.6rem; font-size: 0.9rem;
    font-family: inherit; resize: vertical;
  }
  .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
    outline: none; border-color: var(--bronze);
  }

  .hint { color: var(--ash); font-size: 0.78rem; }

  .launch-btn { width: 100%; margin-top: 0.5rem; }

  .error-msg { color: #e06c75; font-size: 0.85rem; margin: 0.25rem 0; }

  .attack-list { display: flex; flex-direction: column; gap: 0.75rem; }
  .attack-item { border: 1px solid #333; border-radius: 6px; padding: 0.75rem; }
  .attack-item.done { opacity: 0.9; }

  .attack-header {
    display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;
    margin-bottom: 0.4rem;
  }
  .attack-type { font-weight: 600; color: var(--bronze); font-size: 0.85rem; }
  .attack-target { color: var(--ash-light); font-size: 0.85rem; flex: 1; }

  .badge-success { background: #2d6a4f; color: #95d5b2; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.75rem; }
  .badge-danger  { background: #5c2121; color: #e06c75; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.75rem; }

  .btn-sm { padding: 0.2rem 0.6rem; font-size: 0.8rem; }

  .progress-line {
    font-size: 0.8rem; color: var(--ash); font-family: monospace;
    white-space: pre-wrap; word-break: break-all;
  }

  .result-block { margin-top: 0.5rem; }
  .result-meta { display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.8rem; color: var(--ash); margin-bottom: 0.5rem; }
  .result-meta code { color: var(--ash-light); }

  .file-preview {
    background: #111; border: 1px solid #333; border-radius: 4px;
    padding: 0.5rem; font-size: 0.75rem; color: var(--ash-light);
    max-height: 200px; overflow: auto; white-space: pre-wrap; word-break: break-all;
  }

  .creds-found { font-size: 0.85rem; }
  .creds-found strong { color: #e5c07b; }
  .creds-found ul { margin: 0.3rem 0 0 1rem; }
  .creds-found li { margin: 0.15rem 0; }
  .creds-found code { color: #98c379; }

  .no-creds { font-size: 0.85rem; color: var(--ash); margin: 0.25rem 0; }

  .disclaimer {
    font-size: 0.8rem; color: var(--ash); border-color: #5c3a1e;
    background: rgba(92, 58, 30, 0.15);
  }
  .disclaimer strong { color: #e5c07b; }
</style>
