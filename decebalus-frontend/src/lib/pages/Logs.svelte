<script lang="ts">
  import { onMount } from 'svelte';
  import { wsMessages } from '../stores/websocketStore';
  import { getLogs, getJobs, type Log, type Job } from '../api';
  import { fmtDate } from '../utils';

  const PAGE_SIZE = 50;

  let logs: Log[] = [];
  let jobs: Job[] = [];
  let error = '';
  let loading = true;
  let refreshing = false;
  let shown = PAGE_SIZE;

  let filterSeverity = 'all';
  let filterJobType = 'all';
  let searchJobId = '';

  onMount(async () => {
    await refresh();
    loading = false;
  });

  async function refresh() {
    refreshing = true;
    try {
      [logs, jobs] = await Promise.all([getLogs(), getJobs()]);
      error = '';
    } catch (e: any) {
      error = e.message;
    } finally {
      refreshing = false;
    }
  }

  $: if ($wsMessages) {
    const msg = $wsMessages;
    if (typeof msg === 'string' && msg.startsWith('job_')) refresh();
  }

  // Map job_id → job_type for the type filter
  $: jobTypeMap = new Map<string, string>(jobs.map(j => [j.id, j.job_type]));

  // Unique job types present in current job list, sorted
  $: jobTypes = [...new Set(jobs.map(j => j.job_type))].sort();

  $: filtered = logs
    .filter(l => filterSeverity === 'all' || l.severity === filterSeverity)
    .filter(l => filterJobType === 'all' || (l.job_id != null && jobTypeMap.get(l.job_id) === filterJobType))
    .filter(l => searchJobId.trim() === '' || (l.job_id ?? '').toLowerCase().includes(searchJobId.trim().toLowerCase()))
    .sort((a, b) => b.created_at.localeCompare(a.created_at));

  $: visible = filtered.slice(0, shown);

  // Reset pagination when filters change
  $: if (filterSeverity || filterJobType || searchJobId) shown = PAGE_SIZE;

  const severityClass: Record<string, string> = {
    ERROR: 'badge badge-danger',
    WARN:  'badge badge-warn',
    INFO:  'badge badge-info',
    DEBUG: 'badge badge-neutral',
  };
</script>

<hgroup>
  <h1>Logs</h1>
  <p>System and scan activity logs</p>
</hgroup>

{#if error}<p class="error">{error}</p>{/if}

<article>
  <header>
    <div class="filters">
      <select bind:value={filterSeverity}>
        <option value="all">All severities</option>
        <option value="DEBUG">DEBUG</option>
        <option value="INFO">INFO</option>
        <option value="WARN">WARN</option>
        <option value="ERROR">ERROR</option>
      </select>
      <select bind:value={filterJobType}>
        <option value="all">All job types</option>
        {#each jobTypes as type}
          <option value={type}>{type}</option>
        {/each}
      </select>
      <input
        type="search"
        placeholder="Filter by job ID…"
        bind:value={searchJobId}
        class="job-id-search"
      />
    </div>
    <button class="outline secondary" on:click={refresh} disabled={refreshing} aria-busy={refreshing}>Refresh</button>
  </header>

  {#if loading}
    <p aria-busy="true">Loading...</p>
  {:else if filtered.length === 0}
    <p>No logs match the current filters.</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Job ID</th>
            <th>Time</th>
            <th>Severity</th>
            <th>Service</th>
            <th>Module</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {#each visible as log}
            <tr>
              <td class="job-id-cell">{log.job_id ? log.job_id.slice(0, 8) : '—'}</td>
              <td class="nowrap">{fmtDate(log.created_at)}</td>
              <td><span class={severityClass[log.severity] ?? 'badge badge-neutral'}>{log.severity}</span></td>
              <td class="nowrap"><code>{log.service}</code></td>
              <td class="nowrap">{log.module ?? '—'}</td>
              <td class="log-content">{log.content}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    {#if shown < filtered.length}
      <footer>
        <small>{shown} of {filtered.length} entries</small>
        <button class="outline secondary sm" on:click={() => shown += PAGE_SIZE}>
          Load more
        </button>
      </footer>
    {:else}
      <footer>
        <small>{filtered.length} {filtered.length === 1 ? 'entry' : 'entries'}</small>
      </footer>
    {/if}
  {/if}
</article>

<style>
  article header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  .filters {
    display: flex;
    gap: 0.75rem;
    flex-wrap: wrap;
  }

  .filters select {
    width: auto;
    margin: 0;
    padding: 0.3rem 0.6rem;
    font-size: 0.875rem;
  }

  .filters .job-id-search {
    width: auto;
    min-width: 220px;
    margin: 0;
    font-size: 0.875rem;
  }

  table {
    font-size: 0.875rem;
  }

  .nowrap { white-space: nowrap; }

  .log-content {
    word-break: break-word;
    width: 100%;
  }

  .job-id-cell {
    font-family: monospace;
    font-size: 0.75rem;
    color: var(--color-ash);
    white-space: nowrap;
  }

  article footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 0.75rem;
    padding-top: 0.75rem;
    border-top: 1px solid var(--pico-muted-border-color);
    color: var(--color-ash);
  }
</style>
