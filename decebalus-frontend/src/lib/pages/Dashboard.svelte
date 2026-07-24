<script lang="ts">
  import { onMount } from 'svelte';
  import { wsMessages, connectionStatus } from '../stores/websocketStore';
  import { getJobs, getHosts, cancelJob, getExports, triggerExport, exportDownloadUrl, type Job, type Host, type ExportFile } from '../api';
  import { fmtDate, fmtUnixTs, fmtResults } from '../utils';

  const PER_PAGE = 15;

  let jobs: Job[] = [];
  let hosts: Host[] = [];
  let error = '';
  let loading = true;
  let refreshing = false;
  let expandedJobId: string | null = null;
  let page = 0;

  let exportFiles: ExportFile[] = [];
  let exportError = '';
  let exporting = false;

  onMount(() => {
    // Non-async: Promise chain runs independently so Svelte 5 can't cancel it
    // when the component is destroyed mid-navigation.
    Promise.all([refresh(), refreshExports()]).finally(() => {
      loading = false;
    });

    // Re-fetch data silently whenever the WS reconnects (backend restarted,
    // or page loaded while backend was down and backend came up later).
    let isFirst = true;
    const unsub = connectionStatus.subscribe(status => {
      if (isFirst) { isFirst = false; return; }
      if (status === 'connected') {
        refresh();
        refreshExports();
      }
    });

    return unsub;
  });

  async function refresh() {
    refreshing = true;
    try {
      [jobs, hosts] = await Promise.all([getJobs(), getHosts()]);
      error = '';
    } catch (e: any) {
      error = e.message;
    } finally {
      refreshing = false;
    }
  }

  async function refreshExports() {
    try {
      exportFiles = await getExports();
      exportError = '';
    } catch (e: any) {
      exportError = e.message;
    }
  }

  async function handleExport() {
    exporting = true;
    exportError = '';
    try {
      await triggerExport();
      await refresh(); // show the new job in the history table
    } catch (e: any) {
      exportError = e.message;
    } finally {
      exporting = false;
    }
  }

  function fmtBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  }

  $: if ($wsMessages) {
    const msg = $wsMessages;
    if (typeof msg === 'string' && msg.startsWith('job_')) {
      refresh();
      // Refresh export list whenever an export job finishes
      if (msg.startsWith('job_completed:') || msg.startsWith('job_failed:')) {
        refreshExports();
      }
    }
  }

  async function handleCancel(id: string) {
    try {
      await cancelJob(id);
      await refresh();
    } catch (e: any) {
      error = e.message;
    }
  }

  function toggleResults(id: string) {
    expandedJobId = expandedJobId === id ? null : id;
  }

  function goToPage(p: number) {
    page = p;
    expandedJobId = null;
  }

  $: running   = jobs.filter(j => j.status === 'running');
  $: queued    = jobs.filter(j => j.status === 'queued');
  $: completed = jobs.filter(j => j.status === 'completed');
  $: failed    = jobs.filter(j => j.status === 'failed');
  $: sorted    = [...jobs].sort((a, b) => b.created_at.localeCompare(a.created_at));
  $: pageCount = Math.max(1, Math.ceil(sorted.length / PER_PAGE));
  $: if (page >= pageCount) page = pageCount - 1;
  $: paged     = sorted.slice(page * PER_PAGE, (page + 1) * PER_PAGE);

  const statusClass: Record<string, string> = {
    running:   'badge badge-warn',
    queued:    'badge badge-info',
    completed: 'badge badge-success',
    failed:    'badge badge-danger',
    cancelled: 'badge badge-neutral',
    scheduled: 'badge badge-neutral',
  };
</script>

{#if loading}
  <p aria-busy="true">Loading…</p>
{:else}
  {#if error}<p class="error">{error}</p>{/if}

  <hgroup>
    <h1>
      Dashboard
      <span class="badge badge-live" aria-label="Live updates active">Live</span>
    </h1>
    <p>Monitor Decebalus activity</p>
  </hgroup>

  <div class="stats-grid">
    <article class="stat-card">
      <div class="stat-icon running-icon" aria-hidden="true">
        <!-- Activity lines -->
        <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg">
          <polyline points="2,11 6,5 10,14 14,8 18,11 22,11"
                    stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
        </svg>
      </div>
      <div class="stat-body">
        <span class="stat-number {running.length + queued.length > 0 ? 'active' : ''}">
          {running.length + queued.length}
        </span>
        <span class="stat-label">Active Jobs</span>
      </div>
    </article>

    <article class="stat-card">
      <div class="stat-icon hosts-icon" aria-hidden="true">
        <!-- Network nodes -->
        <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="11" cy="4"  r="2.5" stroke="currentColor" stroke-width="1.6"/>
          <circle cx="4"  cy="17" r="2.5" stroke="currentColor" stroke-width="1.6"/>
          <circle cx="18" cy="17" r="2.5" stroke="currentColor" stroke-width="1.6"/>
          <line x1="11" y1="6.5" x2="4"  y2="14.5" stroke="currentColor" stroke-width="1.3"/>
          <line x1="11" y1="6.5" x2="18" y2="14.5" stroke="currentColor" stroke-width="1.3"/>
          <line x1="6.5" y1="17" x2="15.5" y2="17" stroke="currentColor" stroke-width="1.3"/>
        </svg>
      </div>
      <div class="stat-body">
        <span class="stat-number {hosts.length > 0 ? 'active' : ''}">{hosts.length}</span>
        <span class="stat-label">Hosts Discovered</span>
      </div>
    </article>

    <article class="stat-card">
      <div class="stat-icon done-icon" aria-hidden="true">
        <!-- Checkmark -->
        <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="11" cy="11" r="8.5" stroke="currentColor" stroke-width="1.6"/>
          <polyline points="7,11 10,14 15,8"
                    stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
        </svg>
      </div>
      <div class="stat-body">
        <span class="stat-number {completed.length > 0 ? 'active' : ''}">{completed.length}</span>
        <span class="stat-label">Jobs Completed</span>
      </div>
    </article>

    <article class="stat-card">
      <div class="stat-icon fail-icon" aria-hidden="true">
        <!-- X circle -->
        <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="11" cy="11" r="8.5" stroke="currentColor" stroke-width="1.6"/>
          <line x1="7.5" y1="7.5" x2="14.5" y2="14.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
          <line x1="14.5" y1="7.5" x2="7.5" y2="14.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
        </svg>
      </div>
      <div class="stat-body">
        <span class="stat-number {failed.length > 0 ? 'fail' : ''}">{failed.length}</span>
        <span class="stat-label">Jobs Failed</span>
      </div>
    </article>
  </div>

  <article>
    <header>
      <strong>
        Job History
        {#if sorted.length > 0}
          <span class="badge badge-neutral" style="font-weight:400; margin-left:0.4rem">
            {sorted.length}
          </span>
        {/if}
      </strong>
      <button class="outline secondary sm" on:click={refresh} disabled={refreshing}
              aria-busy={refreshing} aria-label="Refresh job list">
        Refresh
      </button>
    </header>

    {#if sorted.length === 0}
      <div class="empty-state">
        <p>No jobs yet — go to <a href="/recon">Recon</a> to start a scan.</p>
      </div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Target</th>
              <th>Status</th>
              <th>Started</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each paged as job}
              <tr>
                <td><code>{job.job_type}</code></td>
                <td class="target-cell">{job.config?.target ?? '—'}</td>
                <td><span class={statusClass[job.status] ?? 'badge badge-neutral'}>{job.status}</span></td>
                <td class="time-cell">
                  {#if job.scheduled_at}
                    <span class="scheduled-for">Sched: {fmtUnixTs(job.scheduled_at)}</span>
                  {:else}
                    {fmtDate(job.created_at)}
                  {/if}
                </td>
                <td class="actions">
                  {#if job.status === 'running' || job.status === 'queued' || job.status === 'scheduled'}
                    <button class="outline secondary sm"
                            on:click={() => handleCancel(job.id)}
                            aria-label="Cancel job {job.id}">
                      Cancel
                    </button>
                  {/if}
                  {#if job.results}
                    <button
                      class="outline sm"
                      on:click={() => toggleResults(job.id)}
                      aria-expanded={expandedJobId === job.id}
                    >
                      {expandedJobId === job.id ? 'Hide' : 'Results'}
                    </button>
                  {/if}
                </td>
              </tr>
              {#if expandedJobId === job.id && job.results}
                <tr class="detail-row">
                  <td colspan="5">
                    <pre>{fmtResults(job.results)}</pre>
                  </td>
                </tr>
              {/if}
            {/each}
          </tbody>
        </table>
      </div>

      {#if pageCount > 1}
        <footer class="pagination">
          <button
            class="outline secondary sm"
            disabled={page === 0}
            on:click={() => goToPage(page - 1)}
          >← Prev</button>
          <small>Page {page + 1} of {pageCount} &middot; {sorted.length} total</small>
          <button
            class="outline secondary sm"
            disabled={page >= pageCount - 1}
            on:click={() => goToPage(page + 1)}
          >Next →</button>
        </footer>
      {:else}
        <footer class="pagination">
          <small>{sorted.length} {sorted.length === 1 ? 'job' : 'jobs'} total</small>
        </footer>
      {/if}
    {/if}
  </article>

  <!-- ── Export ─────────────────────────────────── -->
  <article>
    <header>
      <strong>Data Export</strong>
      <button
        on:click={handleExport}
        disabled={exporting}
        aria-busy={exporting}
      >
        {exporting ? 'Queuing…' : 'Export Now'}
      </button>
    </header>

    {#if exportError}<p class="error" role="alert">{exportError}</p>{/if}

    {#if exportFiles.length === 0}
      <div class="empty-state">
        <p>No exports yet — click <strong>Export Now</strong> to generate one.</p>
      </div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>File</th>
              <th>Size</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each exportFiles as file}
              <tr>
                <td class="export-filename">{file.filename}</td>
                <td class="export-size">{fmtBytes(file.size)}</td>
                <td class="time-cell">
                  {file.modified_at ? fmtUnixTs(file.modified_at) : '—'}
                </td>
                <td>
                  <a
                    href={exportDownloadUrl(file.filename)}
                    download={file.filename}
                    class="outline sm"
                    role="button"
                  >Download</a>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </article>
{/if}

<style>
  /* ── Stats grid ────────────────────────────── */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 1.25rem;
  }

  .stat-card {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 1.1rem 1.25rem !important;
    border-left: 3px solid var(--border-bronze-subtle) !important;
    transition: border-color 0.2s ease !important;
  }

  .stat-card:hover {
    border-left-color: var(--border-bronze-accent) !important;
  }

  /* Icon column */
  .stat-icon {
    flex-shrink: 0;
    width: 2.4rem;
    height: 2.4rem;
    border-radius: 0.5rem;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--surface-raised);
  }

  .running-icon { color: var(--status-running); }
  .hosts-icon   { color: var(--color-info); }
  .done-icon    { color: var(--color-success); }
  .fail-icon    { color: var(--color-danger); }

  /* Text column */
  .stat-body {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
  }

  .stat-number {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
    color: var(--color-ash);
    transition: color 0.2s ease, text-shadow 0.2s ease;
  }

  .stat-number.active {
    color: var(--color-bronze-bright);
    text-shadow: 0 0 18px var(--color-bronze-glow);
  }

  .stat-number.fail {
    color: var(--color-danger);
  }

  .stat-label {
    font-size: 0.8rem;
    color: var(--color-ash);
    letter-spacing: 0.02em;
  }

  /* ── Job table extras ──────────────────────── */
  .target-cell {
    font-family: monospace;
    font-size: 0.82rem;
    color: var(--color-ash-light);
    max-width: 180px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .time-cell {
    white-space: nowrap;
    font-size: 0.82rem;
    color: var(--color-ash);
  }

  .scheduled-for {
    font-size: 0.82rem;
    color: var(--color-ash);
  }

  .actions {
    display: flex;
    gap: 0.4rem;
    align-items: center;
    white-space: nowrap;
  }

  /* ── Export table ──────────────────────────── */
  .export-filename {
    font-family: monospace;
    font-size: 0.82rem;
    color: var(--color-ash-light);
  }

  .export-size {
    white-space: nowrap;
    font-size: 0.82rem;
    color: var(--color-ash);
    text-align: right;
  }

  /* ── Responsive ────────────────────────────── */
  @media (max-width: 900px) {
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
  }

  @media (max-width: 480px) {
    .stats-grid { grid-template-columns: 1fr; }
  }
</style>
