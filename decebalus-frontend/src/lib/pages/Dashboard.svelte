<script lang="ts">
  import { onMount } from 'svelte';
  import { wsMessages } from '../stores/websocketStore';
  import { getJobs, getHosts, cancelJob, type Job, type Host } from '../api';
  import { fmtDate, fmtUnixTs, fmtResults } from '../utils';

  const PER_PAGE = 15;

  let jobs: Job[] = [];
  let hosts: Host[] = [];
  let error = '';
  let loading = true;
  let refreshing = false;
  let expandedJobId: string | null = null;
  let page = 0;

  onMount(async () => {
    await refresh();
    loading = false;
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

  $: if ($wsMessages) {
    const msg = $wsMessages;
    if (typeof msg === 'string' && msg.startsWith('job_')) refresh();
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

  $: running  = jobs.filter(j => j.status === 'running');
  $: queued   = jobs.filter(j => j.status === 'queued');
  $: sorted   = [...jobs].sort((a, b) => b.created_at.localeCompare(a.created_at));
  $: pageCount = Math.max(1, Math.ceil(sorted.length / PER_PAGE));
  $: if (page >= pageCount) page = pageCount - 1;
  $: paged    = sorted.slice(page * PER_PAGE, (page + 1) * PER_PAGE);

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
  <p aria-busy="true">Loading...</p>
{:else}
  {#if error}<p class="error">{error}</p>{/if}

  <hgroup>
    <h1>Dashboard</h1>
    <p>Monitor Decebalus activity</p>
  </hgroup>

  <div class="stats-grid">
    <article>
      <h2>{running.length + queued.length}</h2>
      <p>Active Jobs</p>
    </article>
    <article>
      <h2>{hosts.length}</h2>
      <p>Hosts Discovered</p>
    </article>
    <article>
      <h2>{jobs.filter(j => j.status === 'completed').length}</h2>
      <p>Jobs Completed</p>
    </article>
  </div>

  <article>
    <header>
      <strong>Job History</strong>
      <button class="outline secondary" on:click={refresh} disabled={refreshing} aria-busy={refreshing}>Refresh</button>
    </header>

    {#if sorted.length === 0}
      <p>No jobs yet. Go to Recon to start a scan.</p>
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
                <td>{job.config.target ?? '—'}</td>
                <td><span class={statusClass[job.status] ?? 'badge badge-neutral'}>{job.status}</span></td>
                <td>
                  {#if job.scheduled_at}
                    <span class="scheduled-for">Scheduled: {fmtUnixTs(job.scheduled_at)}</span>
                  {:else}
                    {fmtDate(job.created_at)}
                  {/if}
                </td>
                <td class="actions">
                  {#if job.status === 'running' || job.status === 'queued' || job.status === 'scheduled'}
                    <button class="outline secondary sm" on:click={() => handleCancel(job.id)}>
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
{/if}

<style>
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
    margin-bottom: 1rem;
  }

  article h2 {
    font-size: 2.5rem;
    font-weight: 700;
    color: var(--color-bronze);
    margin: 0;
  }

  article p {
    color: var(--color-ash);
    margin: 0.25rem 0 0;
  }

  article header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .scheduled-for {
    font-size: 0.85rem;
    color: var(--color-ash);
  }

  .actions {
    display: flex;
    gap: 0.4rem;
    align-items: center;
    white-space: nowrap;
  }

  .pagination {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 0.75rem;
    padding-top: 0.75rem;
    border-top: 1px solid var(--pico-muted-border-color);
    color: var(--color-ash);
  }

  @media (max-width: 640px) {
    .stats-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
