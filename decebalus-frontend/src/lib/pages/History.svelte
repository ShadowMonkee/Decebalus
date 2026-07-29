<script lang="ts">
  import { onMount } from 'svelte';
  import { wsMessages } from '../stores/websocketStore';
  import { getHistory, type HostEvent } from '../api';
  import { fmtDate } from '../utils';

  let events: HostEvent[] = [];
  let loading = true;
  let error = '';
  let filter: string = 'all';

  async function refresh() {
    try {
      events = await getHistory(200);
      error = '';
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  onMount(refresh);

  // New change events are surfaced via host_found/host_down/scan broadcasts; refresh on those.
  $: if ($wsMessages) {
    const m = $wsMessages;
    if (typeof m === 'string' && (m.startsWith('host_') || m.startsWith('job_completed:'))) {
      refresh();
    }
  }

  const labels: Record<string, string> = {
    host_new: 'New host',
    host_up: 'Host up',
    host_down: 'Host down',
    port_opened: 'Port opened',
    vuln_new: 'New vulnerability',
  };
  const eventClass: Record<string, string> = {
    host_new: 'badge-info',
    host_up: 'badge-success',
    host_down: 'badge-neutral',
    port_opened: 'badge-warn',
    vuln_new: 'badge-danger',
  };
  const severityClass: Record<string, string> = {
    CRITICAL: 'badge-danger',
    HIGH: 'badge-warn',
    MEDIUM: 'badge-info',
  };

  $: filtered = filter === 'all' ? events : events.filter(e => e.event_type === filter);
</script>

<hgroup>
  <h1>History</h1>
  <p>Network change timeline — new hosts, status changes, newly opened ports, and vulnerabilities.</p>
</hgroup>

{#if loading}
  <p aria-busy="true">Loading history…</p>
{:else if error}
  <p class="error" role="alert">{error}</p>
{:else}
  <div class="toolbar">
    <select bind:value={filter} aria-label="Filter by event type">
      <option value="all">All events</option>
      <option value="host_new">New hosts</option>
      <option value="host_up">Host up</option>
      <option value="host_down">Host down</option>
      <option value="port_opened">Ports opened</option>
      <option value="vuln_new">New vulnerabilities</option>
    </select>
    <button class="outline secondary sm" on:click={refresh}>Refresh</button>
  </div>

  {#if filtered.length === 0}
    <div class="empty-state">
      <p>No changes recorded yet — run a discovery/scan to start building the timeline.</p>
    </div>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>When</th>
            <th>Event</th>
            <th>Host</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as e}
            <tr>
              <td class="time-cell">{fmtDate(e.created_at)}</td>
              <td><span class="badge {eventClass[e.event_type] ?? 'badge-neutral'}">{labels[e.event_type] ?? e.event_type}</span></td>
              <td><code>{e.host_ip}</code></td>
              <td>
                {#if e.event_type === 'vuln_new'}
                  <code>{e.detail}</code>
                  {#if e.severity}<span class="badge {severityClass[e.severity] ?? 'badge-neutral'}" style="margin-left:0.4rem">{e.severity}</span>{/if}
                {:else}
                  {e.detail ?? '—'}
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/if}

<style>
  .toolbar {
    display: flex;
    gap: 0.75rem;
    align-items: center;
    margin-bottom: 1rem;
  }
  .toolbar select { width: auto; margin: 0; }
  .time-cell { white-space: nowrap; font-size: 0.82rem; color: var(--color-ash); }
  .empty-state { padding: 1.5rem; text-align: center; color: var(--color-ash); }
</style>
