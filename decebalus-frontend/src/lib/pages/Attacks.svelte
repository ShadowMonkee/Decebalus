<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { getHosts, getJobs, createAttackJob, cancelJob, getWordlists, getWordlistContent, saveCustomWordlist, type Host, type Job, type WordlistMeta } from '../api';
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
  let concurrency = '20';
  let usernames = '';
  let passwords = '';
  let domain = '';
  let username = '';
  let password = '';
  let remotePath = '/etc/passwd';

  // Saved wordlists (bundled/downloaded/custom) — a dropdown pick takes priority
  // over the pasted textarea for that field.
  let wordlists: WordlistMeta[] = [];
  let usernameWordlistId = '';
  let passwordWordlistId = '';
  let savingField: 'usernames' | 'passwords' | null = null;
  let saveName = '';
  let saveBusy = false;
  let saveError = '';

  // Load a saved list into the editable textarea (a working copy of the original).
  let loadingField: 'usernames' | 'passwords' | null = null;
  let loadNote: { usernames: string; passwords: string } = { usernames: '', passwords: '' };
  let loadError: { usernames: string; passwords: string } = { usernames: '', passwords: '' };

  $: usernameWordlists = wordlists.filter(w => w.category === 'username');
  $: passwordWordlists = wordlists.filter(w => w.category === 'password');

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
      config.concurrency = parseInt(concurrency) || 20;
      const userList = usernames.trim().split('\n').map(s => s.trim()).filter(Boolean);
      const passList = passwords.trim().split('\n').map(s => s.trim()).filter(Boolean);
      if (userList.length) config.usernames = userList;
      if (passList.length) config.passwords = passList;
      if (usernameWordlistId) config.usernames_wordlist_id = usernameWordlistId;
      if (passwordWordlistId) config.passwords_wordlist_id = passwordWordlistId;
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

  async function loadWordlists() {
    try { wordlists = await getWordlists(); } catch { /* wordlists are optional; ignore */ }
  }

  // Pull a selected list's contents into the textarea as an editable working copy.
  // Clears the picker so the (possibly edited) textarea is what the job uses, leaving
  // the original list on disk untouched. Large lists are refused by the backend.
  async function loadIntoEditor(field: 'usernames' | 'passwords') {
    const id = field === 'usernames' ? usernameWordlistId : passwordWordlistId;
    loadNote = { ...loadNote, [field]: '' };
    loadError = { ...loadError, [field]: '' };
    if (!id) { loadError = { ...loadError, [field]: 'Choose a wordlist above first.' }; return; }
    loadingField = field;
    try {
      const wl = await getWordlistContent(id);
      if (field === 'usernames') { usernames = wl.content; usernameWordlistId = ''; }
      else { passwords = wl.content; passwordWordlistId = ''; }
      loadNote = { ...loadNote, [field]: `Loaded a copy of “${wl.name}” (${wl.entry_count.toLocaleString()} entries). The original is untouched — edit freely, then “Save this list…” to keep changes as a new list.` };
    } catch (e: any) {
      loadError = { ...loadError, [field]: e?.message ?? 'Could not load list.' };
    } finally {
      loadingField = null;
    }
  }

  function startSave(field: 'usernames' | 'passwords') {
    savingField = field;
    saveName = '';
    saveError = '';
  }

  function cancelSave() {
    savingField = null;
    saveError = '';
  }

  async function confirmSave() {
    if (!savingField) return;
    const content = savingField === 'usernames' ? usernames : passwords;
    if (!saveName.trim()) { saveError = 'Name is required.'; return; }
    if (!content.trim()) { saveError = 'Nothing to save — paste a list first.'; return; }

    saveBusy = true;
    saveError = '';
    try {
      const category = savingField === 'usernames' ? 'username' : 'password';
      const saved = await saveCustomWordlist(saveName.trim(), category, content);
      await loadWordlists();
      if (savingField === 'usernames') usernameWordlistId = saved.id;
      else passwordWordlistId = saved.id;
      savingField = null;
    } catch (e: any) {
      saveError = e.message ?? 'Save failed';
    } finally {
      saveBusy = false;
    }
  }

  function parseResult(job: Job): any {
    if (!job.results) return null;
    try { return JSON.parse(job.results); } catch { return null; }
  }

  let unsubscribe: (() => void) | null = null;

  onMount(async () => {
    await refresh();
    await loadWordlists();

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
          <label for="concurrency-input">Concurrency <small>(SSH/FTP are cheap — go high; SMB/RDP shell out per attempt — keep lower. Server caps at 100 regardless.)</small></label>
          <input id="concurrency-input" type="number" bind:value={concurrency} min="1" max="100" />
        </div>
        <div class="form-group">
          <label for="usernames-wordlist-select">Usernames wordlist <small>(use as-is, or load ↓ to view/edit a copy)</small></label>
          <select id="usernames-wordlist-select" bind:value={usernameWordlistId}>
            <option value="">-- none, use pasted list / defaults --</option>
            {#each usernameWordlists as w}
              <option value={w.id}>{w.name} — {w.entry_count} entries ({w.source})</option>
            {/each}
          </select>
          <button type="button" class="outline btn-sm save-list-btn"
                  on:click={() => loadIntoEditor('usernames')}
                  disabled={!usernameWordlistId || loadingField === 'usernames'}>
            {loadingField === 'usernames' ? 'Loading…' : 'Load into editor ↓'}
          </button>
          {#if loadNote.usernames}<p class="load-note">{loadNote.usernames}</p>{/if}
          {#if loadError.usernames}<p class="error-msg">{loadError.usernames}</p>{/if}
        </div>
        <div class="form-group">
          <label for="usernames-input">Usernames <small>(one per line, blank = built-in defaults)</small></label>
          <textarea id="usernames-input" bind:value={usernames} rows="4"
            placeholder="root&#10;pi&#10;admin"></textarea>
          <button type="button" class="outline btn-sm save-list-btn" on:click={() => startSave('usernames')} disabled={!usernames.trim()}>
            Save this list…
          </button>
          {#if savingField === 'usernames'}
            <div class="save-row">
              <input type="text" placeholder="Wordlist name" bind:value={saveName} />
              <button class="btn-sm" on:click={confirmSave} disabled={saveBusy}>{saveBusy ? 'Saving…' : 'Save'}</button>
              <button type="button" class="outline btn-sm" on:click={cancelSave}>Cancel</button>
            </div>
            {#if saveError}<p class="error-msg">{saveError}</p>{/if}
          {/if}
        </div>
        <div class="form-group">
          <label for="passwords-wordlist-select">Passwords wordlist <small>(use as-is, or load ↓ to view/edit a copy)</small></label>
          <select id="passwords-wordlist-select" bind:value={passwordWordlistId}>
            <option value="">-- none, use pasted list / defaults --</option>
            {#each passwordWordlists as w}
              <option value={w.id}>{w.name} — {w.entry_count} entries ({w.source})</option>
            {/each}
          </select>
          <button type="button" class="outline btn-sm save-list-btn"
                  on:click={() => loadIntoEditor('passwords')}
                  disabled={!passwordWordlistId || loadingField === 'passwords'}>
            {loadingField === 'passwords' ? 'Loading…' : 'Load into editor ↓'}
          </button>
          {#if loadNote.passwords}<p class="load-note">{loadNote.passwords}</p>{/if}
          {#if loadError.passwords}<p class="error-msg">{loadError.passwords}</p>{/if}
        </div>
        <div class="form-group">
          <label for="passwords-input">Passwords <small>(one per line, blank = built-in defaults)</small></label>
          <textarea id="passwords-input" bind:value={passwords} rows="4"
            placeholder="raspberry&#10;admin&#10;password"></textarea>
          <button type="button" class="outline btn-sm save-list-btn" on:click={() => startSave('passwords')} disabled={!passwords.trim()}>
            Save this list…
          </button>
          {#if savingField === 'passwords'}
            <div class="save-row">
              <input type="text" placeholder="Wordlist name" bind:value={saveName} />
              <button class="btn-sm" on:click={confirmSave} disabled={saveBusy}>{saveBusy ? 'Saving…' : 'Save'}</button>
              <button type="button" class="outline btn-sm" on:click={cancelSave}>Cancel</button>
            </div>
            {#if saveError}<p class="error-msg">{saveError}</p>{/if}
          {/if}
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

  .save-list-btn { align-self: flex-start; margin-top: 0.15rem; width: auto; }

  .save-row {
    display: flex; gap: 0.5rem; align-items: center; margin-top: 0.4rem;
  }
  .save-row input {
    flex: 1; background: var(--forest-dark, #1a1a1a); border: 1px solid #444;
    border-radius: 4px; color: var(--ash-light); padding: 0.35rem 0.6rem; font-size: 0.85rem;
  }

  .launch-btn { width: 100%; margin-top: 0.5rem; }

  .error-msg { color: var(--clay); font-size: 0.85rem; margin: 0.25rem 0; }

  .attack-list { display: flex; flex-direction: column; gap: 0.75rem; }
  .attack-item { border: 1px solid var(--line); border-radius: var(--radius); padding: 0.75rem; background: var(--surface); }
  .attack-item.done { opacity: 0.9; }

  .attack-header {
    display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;
    margin-bottom: 0.4rem;
  }
  .attack-type { font-weight: 500; color: var(--accent); font-size: 0.85rem; font-family: var(--font-mono); }
  .attack-target { color: var(--text-2); font-size: 0.85rem; flex: 1; font-family: var(--font-mono); }

  .badge-success { background: var(--raised); color: var(--sage); border: 1px solid color-mix(in srgb, var(--sage) 42%, var(--strong)); padding: 0.15rem 0.5rem; border-radius: var(--radius-sm); font-size: 0.7rem; font-family: var(--font-mono); text-transform: uppercase; letter-spacing: 0.08em; }
  .badge-danger  { background: var(--raised); color: var(--clay); border: 1px solid color-mix(in srgb, var(--clay) 42%, var(--strong)); padding: 0.15rem 0.5rem; border-radius: var(--radius-sm); font-size: 0.7rem; font-family: var(--font-mono); text-transform: uppercase; letter-spacing: 0.08em; }

  .btn-sm { padding: 0.2rem 0.6rem; font-size: 0.8rem; }

  .progress-line {
    font-size: 0.8rem; color: var(--ash); font-family: monospace;
    white-space: pre-wrap; word-break: break-all;
  }

  .result-block { margin-top: 0.5rem; }
  .result-meta { display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.8rem; color: var(--ash); margin-bottom: 0.5rem; }
  .result-meta code { color: var(--ash-light); }

  .file-preview {
    background: var(--code-bg); border: 1px solid var(--line); border-radius: var(--radius);
    padding: 0.5rem; font-size: 0.75rem; color: var(--text-2);
    max-height: 200px; overflow: auto; white-space: pre-wrap; word-break: break-all;
  }

  .creds-found { font-size: 0.85rem; }
  .creds-found strong { color: var(--accent); }
  .creds-found ul { margin: 0.3rem 0 0 1rem; }
  .creds-found li { margin: 0.15rem 0; }
  .creds-found code { color: var(--sage); }

  .no-creds { font-size: 0.85rem; color: var(--text-3); margin: 0.25rem 0; }

  .disclaimer {
    font-size: 0.8rem; color: var(--text-3); border-left: 2px solid var(--amber);
    background: var(--raised);
  }
  .disclaimer strong { color: var(--amber); }
</style>
