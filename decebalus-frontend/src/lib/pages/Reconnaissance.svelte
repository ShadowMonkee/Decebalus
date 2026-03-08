<script lang="ts">
  import { onMount } from 'svelte';
  import { wsMessages } from '../stores/websocketStore';
  import { getHosts, getJobs, createJob, cancelJob, scheduleJob, type Host, type Job } from '../api';
  import { fmtDate } from '../utils';

  let hosts: Host[] = [];
  let jobs: Job[] = [];
  let target = 'self';
  let error = '';
  let success = '';
  let submitting = false;
  let scanningIps = new Set<string>();
  let scanningAll = false;
  let refreshing = false;
  let expandedHostIp: string | null = null;
  let scheduleMode = false;
  let scheduledAt = '';
  let scanProgress = new Map<string, string>(); // jobId → latest phase message

  function minDatetime(): string {
    const d = new Date(Date.now() + 60_000);
    const p = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
  }

  onMount(async () => {
    await refresh();
  });

  async function refresh() {
    refreshing = true;
    try {
      [hosts, jobs] = await Promise.all([getHosts(), getJobs()]);
      error = '';
    } catch (e: any) {
      error = e.message;
    } finally {
      refreshing = false;
    }
  }

  $: if ($wsMessages) {
    const msg = $wsMessages;
    if (typeof msg === 'string') {
      if (msg.startsWith('scan_progress:')) {
        const rest = msg.slice('scan_progress:'.length);
        const colon = rest.indexOf(':');
        if (colon !== -1) {
          const jobId = rest.slice(0, colon);
          const phase = rest.slice(colon + 1);
          scanProgress = new Map(scanProgress).set(jobId, phase);
        }
      } else if (msg.startsWith('job_completed:') || msg.startsWith('job_failed:')) {
        const jobId = msg.split(':')[1];
        if (jobId) {
          scanProgress = new Map(scanProgress);
          scanProgress.delete(jobId);
        }
        refresh();
      } else if (msg.startsWith('job_')) {
        refresh();
      }
    }
  }

  async function startDiscovery() {
    submitting = true;
    error = '';
    try {
      const t = target.trim() || 'self';
      if (scheduleMode) {
        if (!scheduledAt) { error = 'Please pick a date and time.'; submitting = false; return; }
        const ts = Math.floor(new Date(scheduledAt).getTime() / 1000);
        await scheduleJob('discovery', t, ts);
        scheduleMode = false;
        scheduledAt = '';
        success = 'Discovery scan scheduled.';
      } else {
        await createJob('discovery', t);
        success = '';
      }
      await refresh();
    } catch (e: any) {
      error = e.message;
    } finally {
      submitting = false;
    }
  }

  async function startFullPortScan() {
    if (scanningAll) return;
    error = '';
    scanningAll = true;
    try {
      await createJob('port-scan');
      await refresh();
    } catch (e: any) {
      error = e.message;
    } finally {
      scanningAll = false;
    }
  }

  async function startPortScan(ip: string) {
    if (scanningIps.has(ip)) return;
    error = '';
    scanningIps = new Set(scanningIps).add(ip);
    try {
      await createJob('port-scan', ip);
      await refresh();
    } catch (e: any) {
      error = e.message;
    } finally {
      scanningIps = new Set([...scanningIps].filter(x => x !== ip));
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

  function toggleDetail(ip: string) {
    expandedHostIp = expandedHostIp === ip ? null : ip;
  }

  // Find an active discovery job
  $: activeDiscovery = jobs.find(
    j => j.job_type === 'discovery' && (j.status === 'running' || j.status === 'queued')
  );

  // Find a running/queued port-scan job for a given host IP, or any full scan (no target)
  function portScanFor(ip: string): Job | undefined {
    return jobs.find(
      j => j.job_type === 'port-scan' &&
           (j.config.target === ip || !j.config.target) &&
           (j.status === 'running' || j.status === 'queued')
    );
  }

  let scanningNmapIps = new Set<string>();
  let scanningNmapAll = false;

  async function startNmapScan(ip: string) {
    if (scanningNmapIps.has(ip)) return;
    error = '';
    scanningNmapIps = new Set(scanningNmapIps).add(ip);
    try {
      await createJob('nmap-scan', ip);
      await refresh();
    } catch (e: any) {
      error = e.message;
    } finally {
      scanningNmapIps = new Set([...scanningNmapIps].filter(x => x !== ip));
    }
  }

  async function startFullNmapScan() {
    if (scanningNmapAll) return;
    error = '';
    scanningNmapAll = true;
    try {
      await createJob('nmap-scan');
      await refresh();
    } catch (e: any) {
      error = e.message;
    } finally {
      scanningNmapAll = false;
    }
  }

  function nmapScanFor(ip: string): Job | undefined {
    return jobs.find(
      j => j.job_type === 'nmap-scan' &&
           (j.config.target === ip || !j.config.target) &&
           (j.status === 'running' || j.status === 'queued')
    );
  }

  $: activeFullNmapScan = jobs.find(
    j => j.job_type === 'nmap-scan' && !j.config.target &&
         (j.status === 'running' || j.status === 'queued')
  );

  $: activeFullScan = jobs.find(
    j => j.job_type === 'port-scan' && !j.config.target &&
         (j.status === 'running' || j.status === 'queued')
  );

  function openPorts(host: Host): string {
    const open = host.ports.filter(p => p.status === 'open').map(p => p.number);
    return open.length ? open.join(', ') : '—';
  }
</script>

<hgroup>
  <h1>Reconnaissance</h1>
  <p>Discover hosts and scan open ports on your network</p>
</hgroup>

{#if error}<p class="error">{error}</p>{/if}
{#if success}<p class="success">{success}</p>{/if}

<!-- Discovery form / active scan status -->
<article>
  <header><strong>Network Discovery</strong></header>

  {#if activeDiscovery}
    <p>
      Scan running on <code>{activeDiscovery.config.target ?? '—'}</code>
      <span class="badge badge-warn">running</span>
    </p>
    <button class="outline secondary" on:click={() => handleCancel(activeDiscovery.id)}>
      Cancel Scan
    </button>
  {:else}
    <label for="target">
      Target — CIDR range (e.g. <code>192.168.1.0/24</code>) or <code>self</code> to auto-detect
    </label>
    <div class="input-row">
      <input
        id="target"
        type="text"
        bind:value={target}
        placeholder="192.168.1.0/24 or self"
      />
      <label class="schedule-toggle">
        <input type="checkbox" bind:checked={scheduleMode} role="switch" />
        Schedule
      </label>
      <button on:click={startDiscovery} disabled={submitting} aria-busy={submitting}>
        {submitting ? 'Starting...' : scheduleMode ? 'Schedule' : 'Start Discovery'}
      </button>
    </div>
    {#if scheduleMode}
      <div class="schedule-row">
        <label for="scheduled-at">Run at</label>
        <input
          id="scheduled-at"
          type="datetime-local"
          bind:value={scheduledAt}
          min={minDatetime()}
        />
      </div>
    {/if}
  {/if}
</article>

<!-- Hosts table -->
<article>
  <header>
    <strong>Discovered Hosts ({hosts.length})</strong>
    <div class="header-actions">
      {#if activeFullNmapScan}
        <span class="badge badge-warn">nmap scanning all</span>
        {#if scanProgress.get(activeFullNmapScan.id)}
          <span class="scan-phase">{scanProgress.get(activeFullNmapScan.id)}</span>
        {/if}
        <button class="outline secondary sm" on:click={() => handleCancel(activeFullNmapScan.id)}>Cancel</button>
      {:else}
        <button
          class="outline sm"
          on:click={startFullNmapScan}
          disabled={scanningNmapAll || hosts.length === 0}
          aria-busy={scanningNmapAll}
        >Nmap All</button>
      {/if}
      {#if activeFullScan}
        <span class="badge badge-warn">scanning all hosts</span>
        {#if scanProgress.get(activeFullScan.id)}
          <span class="scan-phase">{scanProgress.get(activeFullScan.id)}</span>
        {/if}
        <button class="outline secondary sm" on:click={() => handleCancel(activeFullScan.id)}>Cancel</button>
      {:else}
        <button
          class="outline sm"
          on:click={startFullPortScan}
          disabled={scanningAll || hosts.length === 0}
          aria-busy={scanningAll}
        >Scan All Ports</button>
      {/if}
      <button class="outline secondary sm" on:click={refresh} disabled={refreshing} aria-busy={refreshing}>Refresh</button>
    </div>
  </header>

  {#if hosts.length === 0}
    <p>No hosts discovered yet. Run a network discovery scan above.</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>IP</th>
            <th>Hostname</th>
            <th>MAC</th>
            <th>Open Ports</th>
            <th>Last Seen</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each hosts as host}
            {@const scanning = portScanFor(host.ip)}
            {@const nmapJob = nmapScanFor(host.ip)}
            <tr>
              <td><code>{host.ip}</code></td>
              <td>{host.hostname ?? '—'}</td>
              <td><code>{host.mac_address ?? '—'}</code></td>
              <td>{openPorts(host)}</td>
              <td>{fmtDate(host.last_seen)}</td>
              <td class="actions">
                {#if scanning}
                  <span class="badge badge-warn" title={scanProgress.get(scanning.id) ?? 'scanning'}>scanning</span>
                  <button class="outline secondary sm" on:click={() => handleCancel(scanning.id)}>Cancel</button>
                {:else}
                  <button
                    class="outline sm"
                    on:click={() => startPortScan(host.ip)}
                    disabled={scanningIps.has(host.ip)}
                    aria-busy={scanningIps.has(host.ip)}
                  >Port Scan</button>
                {/if}
                {#if nmapJob}
                  <span class="badge badge-warn" title={scanProgress.get(nmapJob.id) ?? 'running nmap'}>nmap</span>
                  <button class="outline secondary sm" on:click={() => handleCancel(nmapJob.id)}>Cancel</button>
                {:else}
                  <button
                    class="outline sm"
                    on:click={() => startNmapScan(host.ip)}
                    disabled={scanningNmapIps.has(host.ip)}
                    aria-busy={scanningNmapIps.has(host.ip)}
                  >Nmap</button>
                {/if}
                <button
                  class="outline sm"
                  on:click={() => toggleDetail(host.ip)}
                  aria-expanded={expandedHostIp === host.ip}
                >{expandedHostIp === host.ip ? 'Hide' : 'Details'}</button>
              </td>
            </tr>
            {#if expandedHostIp === host.ip}
              <tr class="detail-row">
                <td colspan="6">
                  <div class="host-detail">
                    <div class="detail-meta">
                      {#if host.os}<span><strong>OS:</strong> {host.os}</span>{/if}
                      {#if host.device_type}<span><strong>Type:</strong> {host.device_type}</span>{/if}
                      <span><strong>First seen:</strong> {fmtDate(host.first_seen)}</span>
                      <span><strong>Status:</strong> {host.status}</span>
                    </div>

                    {#if host.ports.length > 0}
                      <table class="ports-table">
                        <thead>
                          <tr>
                            <th>Port</th>
                            <th>Proto</th>
                            <th>Status</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>CPE</th>
                          </tr>
                        </thead>
                        <tbody>
                          {#each host.ports as port}
                            <tr>
                              <td><code>{port.number}</code></td>
                              <td>{port.protocol}</td>
                              <td>
                                <span class="badge {port.status === 'open' ? 'badge-success' : 'badge-neutral'}">
                                  {port.status}
                                </span>
                              </td>
                              <td>{port.service ?? '—'}</td>
                              <td class="port-version">{port.version ?? '—'}</td>
                              <td class="port-cpe" title={port.cpe ?? ''}>{port.cpe ?? '—'}</td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                    {:else}
                      <p class="no-data">No port data — run a port scan to populate.</p>
                    {/if}

                    {#if host.banners.length > 0}
                      <div class="banners">
                        <strong>Banners</strong>
                        {#each host.banners as banner}
                          <pre>{banner}</pre>
                        {/each}
                      </div>
                    {/if}
                  </div>
                </td>
              </tr>
            {/if}
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</article>

<style>
  .input-row {
    display: flex;
    gap: 0.75rem;
    align-items: center;
    margin-top: 0.5rem;
  }

  .input-row input {
    flex: 1;
    margin-bottom: 0;
  }

  .input-row button {
    flex-shrink: 0;
    width: auto;
    margin-bottom: 0;
  }

  .schedule-toggle {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    white-space: nowrap;
    margin: 0;
    cursor: pointer;
    font-size: 0.9rem;
  }

  .schedule-toggle input[type="checkbox"] {
    margin: 0;
  }

  .schedule-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-top: 0.5rem;
  }

  .schedule-row label {
    white-space: nowrap;
    margin: 0;
    font-size: 0.9rem;
  }

  .schedule-row input {
    margin: 0;
    width: auto;
  }

  article header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }

  .header-actions {
    display: flex;
    gap: 0.5rem;
    align-items: center;
  }

  .actions {
    display: flex;
    gap: 0.4rem;
    align-items: center;
    white-space: nowrap;
  }

  /* Host detail panel */
  .host-detail {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .detail-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    font-size: 0.9rem;
    color: var(--color-ash-light);
  }

  .ports-table {
    margin: 0;
    font-size: 0.875rem;
  }

  .ports-table th,
  .ports-table td {
    padding: 0.3rem 0.6rem;
  }

  .banners {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .no-data {
    color: var(--color-ash);
    font-size: 0.875rem;
    margin: 0;
  }

  .port-version {
    font-size: 0.8rem;
    color: var(--color-ash-light);
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .port-cpe {
    font-size: 0.75rem;
    color: var(--color-ash);
    max-width: 220px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: monospace;
  }
</style>
