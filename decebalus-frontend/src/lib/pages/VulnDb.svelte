<script lang="ts">
  import { onMount } from 'svelte';
  import { wsMessages } from '../stores/websocketStore';
  import { listCves, getCve, syncCves, getHosts, type CveDetail } from '../api';
  import { fmtDate } from '../utils';

  let cves: CveDetail[] = [];
  let allHostCveIds: Set<string> = new Set();
  let loading = true;
  let error = '';
  let syncing = false;
  let syncMsg = '';
  let refreshing = false;

  // Filters / sort
  let search = '';
  let filterSeverity = '';
  let sortBy: 'cvss' | 'severity' | 'published' | 'id' = 'cvss';
  let sortDesc = true;

  // Expandable detail
  let expandedId: string | null = null;
  let detailLoading = false;
  let detailError = '';
  let detailData: CveDetail | null = null;

  onMount(async () => {
    await loadAll();
  });

  async function loadAll() {
    loading = true;
    error = '';
    try {
      const [fetchedCves, hosts] = await Promise.all([listCves(), getHosts()]);
      cves = fetchedCves;
      const ids = new Set<string>();
      for (const h of hosts) {
        for (const v of h.vulnerabilities) {
          ids.add(v.id);
        }
      }
      allHostCveIds = ids;
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  async function refresh() {
    refreshing = true;
    await loadAll();
    refreshing = false;
  }

  async function handleSync() {
    syncing = true;
    syncMsg = '';
    error = '';
    try {
      const job = await syncCves();
      syncMsg = `CVE sync job queued (ID: ${job.id.slice(0, 8)}…) — check Logs for progress.`;
    } catch (e: any) {
      error = e.message;
    } finally {
      syncing = false;
    }
  }

  async function toggleDetail(id: string) {
    if (expandedId === id) {
      expandedId = null;
      detailData = null;
      return;
    }
    expandedId = id;
    detailData = null;
    detailError = '';
    detailLoading = true;
    try {
      detailData = await getCve(id);
    } catch (e: any) {
      detailError = e.message;
    } finally {
      detailLoading = false;
    }
  }

  // Derived: CVE IDs in hosts that have no enriched record yet
  $: enrichedIds = new Set(cves.map(c => c.cve_id));
  $: pendingIds = [...allHostCveIds].filter(id => !enrichedIds.has(id));
  $: total = allHostCveIds.size;
  $: enrichedCount = [...allHostCveIds].filter(id => enrichedIds.has(id)).length;
  $: coveragePct = total === 0 ? 100 : Math.round((enrichedCount / total) * 100);

  const severityOrder: Record<string, number> = {
    CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1,
  };

  function cvssDisplay(c: CveDetail): number | null {
    return c.cvss_v3_score ?? c.cvss_v2_score ?? null;
  }

  function severityColor(s: string | null): string {
    switch (s) {
      case 'CRITICAL': return 'badge-danger';
      case 'HIGH':     return 'badge-warn';
      case 'MEDIUM':   return 'badge-info';
      default:         return 'badge-neutral';
    }
  }

  $: filtered = cves
    .filter(c => {
      if (filterSeverity && c.cvss_v3_severity !== filterSeverity && c.cvss_v2_severity !== filterSeverity) return false;
      if (search) {
        const q = search.toLowerCase();
        if (!c.cve_id.toLowerCase().includes(q) && !c.description.toLowerCase().includes(q)) return false;
      }
      return true;
    })
    .sort((a, b) => {
      let diff = 0;
      if (sortBy === 'cvss') {
        diff = (cvssDisplay(a) ?? -1) - (cvssDisplay(b) ?? -1);
      } else if (sortBy === 'severity') {
        const sa = a.cvss_v3_severity ?? a.cvss_v2_severity ?? '';
        const sb = b.cvss_v3_severity ?? b.cvss_v2_severity ?? '';
        diff = (severityOrder[sa] ?? 0) - (severityOrder[sb] ?? 0);
      } else if (sortBy === 'published') {
        diff = (a.published_at ?? '').localeCompare(b.published_at ?? '');
      } else {
        diff = a.cve_id.localeCompare(b.cve_id);
      }
      return sortDesc ? -diff : diff;
    });

  function setSort(col: typeof sortBy) {
    if (sortBy === col) sortDesc = !sortDesc;
    else { sortBy = col; sortDesc = true; }
  }

  function sortIcon(col: typeof sortBy): string {
    if (sortBy !== col) return '↕';
    return sortDesc ? '↓' : '↑';
  }

  // Auto-refresh when a sync job finishes
  $: if ($wsMessages) {
    const msg = $wsMessages;
    if (typeof msg === 'string' && (msg.startsWith('job_completed:') || msg.startsWith('job_failed:'))) {
      refresh();
    }
  }
</script>

<hgroup>
  <h1>Vulnerability Database</h1>
  <p>NVD-enriched CVEs discovered on your network</p>
</hgroup>

{#if error}<p class="error" role="alert">{error}</p>{/if}
{#if syncMsg}<p class="success" role="status">{syncMsg}</p>{/if}

<!-- Coverage stats bar -->
<article class="stats-card">
  <div class="stats-row">
    <div class="stat">
      <span class="stat-num">{total}</span>
      <span class="stat-label">CVEs found on network</span>
    </div>
    <div class="stat">
      <span class="stat-num {enrichedCount > 0 ? 'active' : ''}">{enrichedCount}</span>
      <span class="stat-label">Enriched from NVD</span>
    </div>
    <div class="stat">
      <span class="stat-num {pendingIds.length > 0 ? 'pending' : ''}">{pendingIds.length}</span>
      <span class="stat-label">Pending enrichment</span>
    </div>
    <div class="stat coverage">
      <span class="stat-num {coveragePct === 100 ? 'full' : 'active'}">{coveragePct}%</span>
      <span class="stat-label">Coverage</span>
    </div>
  </div>
  {#if total > 0}
    <div class="progress-bar-wrap" title="{enrichedCount}/{total} CVEs enriched">
      <div class="progress-bar" style="width:{coveragePct}%"></div>
    </div>
  {/if}
  <div class="stats-actions">
    <button
      class="outline sm"
      on:click={handleSync}
      disabled={syncing}
      aria-busy={syncing}
    >{syncing ? 'Syncing…' : 'Sync NVD Now'}</button>
    <button
      class="outline secondary sm"
      on:click={refresh}
      disabled={refreshing}
      aria-busy={refreshing}
    >Refresh</button>
  </div>
</article>

<!-- Pending CVEs (not yet enriched) -->
{#if pendingIds.length > 0}
  <article class="pending-card">
    <header><strong>Pending Enrichment ({pendingIds.length})</strong></header>
    <p class="pending-desc">
      These CVE IDs were found on your network but have not yet been fetched from NVD.
      Run "Sync NVD Now" to enrich them.
    </p>
    <div class="pending-chips">
      {#each pendingIds as id}
        <code class="pending-chip">{id}</code>
      {/each}
    </div>
  </article>
{/if}

<!-- Enriched CVE table -->
<article>
  <header>
    <strong>Enriched CVEs ({filtered.length}{filtered.length !== cves.length ? ` of ${cves.length}` : ''})</strong>
    <div class="filter-bar">
      <input
        type="search"
        placeholder="Search CVE ID or description…"
        bind:value={search}
        class="search-input"
      />
      <select bind:value={filterSeverity} class="severity-filter">
        <option value="">All severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>
    </div>
  </header>

  {#if loading}
    <p aria-busy="true" style="text-align:center;padding:2rem">Loading vulnerability database…</p>
  {:else if cves.length === 0}
    <div class="empty-state">
      <p>No enriched CVEs yet. Run an nmap scan or click "Sync NVD Now" after hosts have been scanned.</p>
    </div>
  {:else if filtered.length === 0}
    <div class="empty-state">
      <p>No CVEs match your current filters.</p>
    </div>
  {:else}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>
              <button class="sort-btn" on:click={() => setSort('id')}>
                CVE ID {sortIcon('id')}
              </button>
            </th>
            <th>
              <button class="sort-btn" on:click={() => setSort('severity')}>
                Severity {sortIcon('severity')}
              </button>
            </th>
            <th>
              <button class="sort-btn" on:click={() => setSort('cvss')}>
                CVSS {sortIcon('cvss')}
              </button>
            </th>
            <th>
              <button class="sort-btn" on:click={() => setSort('published')}>
                Published {sortIcon('published')}
              </button>
            </th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as cve}
            {@const sev = cve.cvss_v3_severity ?? cve.cvss_v2_severity}
            {@const score = cvssDisplay(cve)}
            <tr
              class="cve-row {expandedId === cve.cve_id ? 'expanded' : ''}"
              on:click={() => toggleDetail(cve.cve_id)}
              title="Click to {expandedId === cve.cve_id ? 'collapse' : 'expand'}"
              aria-expanded={expandedId === cve.cve_id}
            >
              <td><code class="cve-id-cell">{cve.cve_id}</code></td>
              <td>
                {#if sev}
                  <span class="badge {severityColor(sev)}">{sev}</span>
                {:else}
                  <span class="badge badge-neutral">—</span>
                {/if}
              </td>
              <td class="score-cell">
                {#if score !== null}
                  <span class="score {sev?.toLowerCase() ?? ''}">{score.toFixed(1)}</span>
                {:else}—{/if}
              </td>
              <td class="date-cell">
                {cve.published_at ? fmtDate(cve.published_at) : '—'}
              </td>
              <td class="desc-cell">
                {cve.description.length > 120 && expandedId !== cve.cve_id
                  ? cve.description.slice(0, 120) + '…'
                  : expandedId !== cve.cve_id ? cve.description : ''}
                {#if expandedId === cve.cve_id}
                  {#if detailLoading}
                    <span aria-busy="true" style="font-style:italic">Loading…</span>
                  {:else if detailError}
                    <span class="error">{detailError}</span>
                  {:else if detailData}
                    {detailData.description}
                  {/if}
                {/if}
              </td>
            </tr>

            {#if expandedId === cve.cve_id && detailData}
              <tr class="detail-row">
                <td colspan="5">
                  <div class="cve-detail">
                    <div class="detail-scores">
                      {#if detailData.cvss_v3_score !== null}
                        <div class="score-block">
                          <span class="score-label">CVSS v3</span>
                          <span class="score-value">{detailData.cvss_v3_score?.toFixed(1)}</span>
                          {#if detailData.cvss_v3_severity}
                            <span class="badge {severityColor(detailData.cvss_v3_severity)} sm">{detailData.cvss_v3_severity}</span>
                          {/if}
                        </div>
                      {/if}
                      {#if detailData.cvss_v2_score !== null}
                        <div class="score-block">
                          <span class="score-label">CVSS v2</span>
                          <span class="score-value">{detailData.cvss_v2_score?.toFixed(1)}</span>
                          {#if detailData.cvss_v2_severity}
                            <span class="badge {severityColor(detailData.cvss_v2_severity)} sm">{detailData.cvss_v2_severity}</span>
                          {/if}
                        </div>
                      {/if}
                      <div class="score-block">
                        <span class="score-label">Fetched</span>
                        <span class="score-value date">{fmtDate(detailData.fetched_at)}</span>
                      </div>
                    </div>

                    {#if detailData.references.length > 0}
                      <div class="ref-section">
                        <strong>References</strong>
                        <ul>
                          {#each detailData.references as ref}
                            <li><a href={ref} target="_blank" rel="noopener noreferrer">{ref}</a></li>
                          {/each}
                        </ul>
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
  /* ── Stats card ──────────────────────────────── */
  .stats-card {
    padding: 1rem 1.25rem;
  }

  .stats-row {
    display: flex;
    gap: 2rem;
    flex-wrap: wrap;
    align-items: flex-end;
    margin-bottom: 0.75rem;
  }

  .stat {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }

  .stat-num {
    font-size: 1.75rem;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    color: var(--color-ash-light);
    line-height: 1;
  }

  .stat-num.active  { color: var(--color-bronze-bright); text-shadow: 0 0 12px var(--color-bronze-glow); }
  .stat-num.pending { color: #eab308; }
  .stat-num.full    { color: #22c55e; }

  .stat-label {
    font-size: 0.75rem;
    color: var(--color-ash);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .coverage { margin-left: auto; }

  .progress-bar-wrap {
    height: 4px;
    background: var(--surface-raised);
    border-radius: 2px;
    overflow: hidden;
    margin-bottom: 0.75rem;
  }

  .progress-bar {
    height: 100%;
    background: linear-gradient(90deg, var(--color-bronze) 0%, var(--color-bronze-bright) 100%);
    border-radius: 2px;
    transition: width 0.4s ease;
  }

  .stats-actions {
    display: flex;
    gap: 0.5rem;
  }

  /* ── Pending card ────────────────────────────── */
  .pending-card {
    border-left: 3px solid #eab308;
  }

  .pending-desc {
    font-size: 0.875rem;
    color: var(--color-ash-light);
    margin-bottom: 0.75rem;
  }

  .pending-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
  }

  .pending-chip {
    background: var(--surface-raised);
    border: 1px solid var(--border-bronze-subtle);
    border-radius: 0.25rem;
    padding: 0.15rem 0.45rem;
    font-size: 0.75rem;
    color: var(--color-ash-light);
  }

  /* ── Filter bar ──────────────────────────────── */
  article header {
    margin-bottom: 0.75rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
  }

  .filter-bar {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    flex-wrap: wrap;
    margin-left: auto;
  }

  .search-input {
    width: 260px;
    margin: 0;
    font-size: 0.875rem;
  }

  .severity-filter {
    width: auto;
    margin: 0;
    font-size: 0.875rem;
  }

  /* ── Sort buttons ────────────────────────────── */
  .sort-btn {
    all: unset;
    cursor: pointer;
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--color-ash-light);
    white-space: nowrap;
    padding: 0.1rem 0.2rem;
    border-radius: 0.2rem;
    transition: color 0.15s;
  }

  .sort-btn:hover { color: var(--color-bronze-bright); }

  /* ── CVE rows ────────────────────────────────── */
  .cve-row {
    cursor: pointer;
    transition: background 0.12s;
  }

  .cve-row:hover { background: var(--surface-raised); }

  .cve-row.expanded {
    background: color-mix(in srgb, var(--color-bronze) 8%, transparent);
  }

  .cve-id-cell {
    font-size: 0.8rem;
    color: var(--color-bronze-bright);
    white-space: nowrap;
  }

  .score-cell {
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }

  .score {
    font-weight: 600;
    font-size: 0.9rem;
  }
  .score.critical { color: #ef4444; }
  .score.high     { color: #f97316; }
  .score.medium   { color: #eab308; }
  .score.low      { color: #22c55e; }

  .date-cell {
    font-size: 0.8rem;
    color: var(--color-ash);
    white-space: nowrap;
  }

  .desc-cell {
    font-size: 0.8rem;
    color: var(--color-ash-light);
    max-width: 400px;
  }

  /* ── Expanded detail panel ───────────────────── */
  .detail-row td {
    background: var(--surface-raised);
    border-top: none;
    padding: 0.75rem 1rem;
  }

  .cve-detail {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .detail-scores {
    display: flex;
    gap: 1.5rem;
    flex-wrap: wrap;
    align-items: center;
  }

  .score-block {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  .score-label {
    font-size: 0.75rem;
    color: var(--color-ash);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .score-value {
    font-size: 1rem;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    color: var(--color-ash-light);
  }

  .score-value.date {
    font-size: 0.85rem;
    font-weight: 400;
  }

  .ref-section {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .ref-section strong {
    font-size: 0.75rem;
    color: var(--color-ash);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .ref-section ul {
    margin: 0;
    padding-left: 1.2rem;
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }

  .ref-section li { font-size: 0.78rem; }

  .ref-section a {
    color: var(--color-bronze-bright);
    word-break: break-all;
  }

  .ref-section a:hover { color: var(--color-bronze); }
</style>
