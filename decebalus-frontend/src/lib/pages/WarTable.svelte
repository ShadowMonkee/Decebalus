<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import {
    getFindings, getHosts, getActiveEngagement, getConfig,
    runFinding, dismissFinding, runEngine,
    type Finding, type Host, type Engagement,
  } from '../api';
  import { wsEvents } from '../stores/websocketStore';

  let findings: Finding[] = [];
  let hosts: Host[] = [];
  let engagement: Engagement | null = null;
  let quiet = false;
  let error = '';
  let busy = false;
  let activity: { at: string; text: string }[] = [];

  async function refresh() {
    try {
      [findings, hosts, engagement] = await Promise.all([getFindings(), getHosts(), getActiveEngagement()]);
      const cfg = await getConfig().catch(() => ({ settings: {} as Record<string, any> }));
      quiet = cfg.settings?.opsec_quiet === true || cfg.settings?.opsec_quiet === 'true';
      error = '';
    } catch (e: any) {
      error = e.message ?? 'Failed to load war table';
    }
  }

  async function evaluate() {
    busy = true;
    try { await runEngine(); await refresh(); }
    catch (e: any) { error = e.message; }
    finally { busy = false; }
  }

  async function run(f: Finding) {
    busy = true;
    try { await runFinding(f.id); pushActivity(`▶ running: ${f.title}`); await refresh(); }
    catch (e: any) { error = e.message; }
    finally { busy = false; }
  }

  async function dismiss(f: Finding) {
    try { await dismissFinding(f.id); await refresh(); }
    catch (e: any) { error = e.message; }
  }

  async function copy(cmd: string) {
    try { await navigator.clipboard.writeText(cmd); pushActivity('⧉ command copied'); }
    catch { /* clipboard may be unavailable */ }
  }

  function pushActivity(text: string) {
    activity = [{ at: new Date().toLocaleTimeString(), text }, ...activity].slice(0, 40);
  }

  // React to structured live events.
  $: if ($wsEvents) {
    const ev = $wsEvents;
    if (ev.type === 'finding') { pushActivity(`✚ finding: ${ev.payload?.title ?? ''}`); scheduleRefresh(); }
    else if (ev.type === 'cred') { pushActivity(`🔑 cred: ${ev.payload?.domain ?? ''}\\${ev.payload?.username ?? ''}`); scheduleRefresh(); }
    else if (ev.type === 'job') { pushActivity(`● job ${ev.payload?.job_type ?? ''}: ${ev.payload?.status ?? ''}`); scheduleRefresh(); }
    else if (ev.type === 'engine') { pushActivity(`⟳ engine: ${ev.payload?.findings ?? 0} findings`); }
  }

  let refreshTimer: ReturnType<typeof setTimeout> | null = null;
  function scheduleRefresh() {
    if (refreshTimer) return;
    refreshTimer = setTimeout(() => { refreshTimer = null; refresh(); }, 600);
  }

  const sevBadge = (s: string) =>
    s === 'critical' || s === 'high' ? 'badge-danger'
    : s === 'medium' ? 'badge-warn'
    : s === 'low' ? 'badge-info'
    : 'badge-neutral';

  $: active = findings.filter(f => f.status !== 'dismissed');
  const openPorts = (h: Host) => h.ports.filter(p => p.status === 'open').length;

  onMount(refresh);
  onDestroy(() => { if (refreshTimer) clearTimeout(refreshTimer); });
</script>

<header class="war-head">
  <div>
    <h2>War Table</h2>
    {#if engagement}
      <p class="eng">
        <span class="badge badge-info">{engagement.name}</span>
        {#if engagement.domain}<span class="badge badge-neutral">{engagement.domain}</span>{/if}
        {#if engagement.scope_cidrs.length}<span class="scope">scope: {engagement.scope_cidrs.join(', ')}</span>{/if}
        {#if quiet}<span class="badge badge-warn" title="OPSEC quiet mode">quiet</span>{/if}
      </p>
    {:else}
      <p class="eng muted">No active engagement — scope-lock is off. Create one under <a href="/engagements">Engagement</a>.</p>
    {/if}
  </div>
  <button class="sm" on:click={evaluate} disabled={busy}>{busy ? 'Working…' : 'Evaluate next moves'}</button>
</header>

{#if error}<p class="error">{error}</p>{/if}

<div class="war-grid">
  <!-- Ranked next moves -->
  <section class="panel">
    <h3>Ranked next moves <span class="count">{active.length}</span></h3>
    {#if active.length === 0}
      <div class="empty-state">Nothing yet. Run discovery/enumeration or click “Evaluate next moves”.</div>
    {:else}
      <ul class="finding-list">
        {#each active as f (f.id)}
          <li class="finding" class:done={f.status === 'done'}>
            <div class="finding-top">
              <span class="score" title="value score">{f.value_score}</span>
              <span class="badge {sevBadge(f.severity)}">{f.severity}</span>
              <span class="finding-title">{f.title}</span>
              <span class="badge badge-neutral status">{f.status}</span>
            </div>
            {#if f.rationale}<p class="rationale">{f.rationale}</p>{/if}
            {#if f.suggested_command}
              <div class="cmd">
                <code>{f.suggested_command}</code>
                <button class="sm ghost" on:click={() => copy(f.suggested_command ?? '')}>Copy</button>
              </div>
            {/if}
            <div class="finding-actions">
              {#if f.job_type && (f.status === 'suggested' || f.status === 'running')}
                <button class="sm" on:click={() => run(f)} disabled={busy}>Run</button>
              {/if}
              <button class="sm ghost" on:click={() => dismiss(f)}>Dismiss</button>
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <!-- Hosts / domain overview -->
  <section class="panel">
    <h3>Hosts <span class="count">{hosts.length}</span></h3>
    {#if hosts.length === 0}
      <div class="empty-state">No hosts discovered yet.</div>
    {:else}
      <div class="table-wrap">
        <table>
          <thead><tr><th></th><th>IP</th><th>Host</th><th>OS</th><th>Ports</th></tr></thead>
          <tbody>
            {#each hosts as h (h.ip)}
              <tr>
                <td><span class="dot {h.status === 'Up' ? 'up' : 'down'}"></span></td>
                <td class="mono">{h.ip}</td>
                <td>{h.hostname ?? '—'}</td>
                <td class="os">{h.os ?? '—'}</td>
                <td>{openPorts(h)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>

  <!-- Live activity -->
  <section class="panel">
    <h3>Activity</h3>
    {#if activity.length === 0}
      <div class="empty-state">Live events will stream here.</div>
    {:else}
      <ul class="activity">
        {#each activity as a}
          <li><span class="ts">{a.at}</span> {a.text}</li>
        {/each}
      </ul>
    {/if}
  </section>
</div>

<style>
  .war-head { display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
  .war-head h2 { margin: 0; }
  .eng { margin: 0.35rem 0 0; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .eng .scope { color: var(--color-ash); font-size: 0.8rem; }
  .eng.muted { color: var(--color-ash); }

  .war-grid { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr) minmax(0, 0.9fr); gap: 1rem; margin-top: 1rem; }
  @media (max-width: 1100px) { .war-grid { grid-template-columns: 1fr; } }

  .panel {
    border: 1px solid var(--border-bronze-subtle);
    border-radius: 8px;
    padding: 0.85rem 1rem;
    background: var(--surface-raised);
  }
  .panel h3 { margin: 0 0 0.75rem; font-size: 0.95rem; display: flex; align-items: center; gap: 0.5rem; }
  .count { color: var(--color-ash); font-weight: 400; font-size: 0.8rem; }

  .finding-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.6rem; }
  .finding { border: 1px solid var(--border-bronze-subtle); border-radius: 6px; padding: 0.6rem 0.7rem; }
  .finding.done { opacity: 0.72; }
  .finding-top { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .finding-title { font-weight: 600; flex: 1; min-width: 8rem; }
  .score { font-variant-numeric: tabular-nums; font-weight: 700; color: var(--color-bronze-bright); min-width: 1.6rem; }
  .status { margin-left: auto; }
  .rationale { margin: 0.4rem 0; color: var(--color-ash-light); font-size: 0.85rem; }
  .cmd { display: flex; align-items: center; gap: 0.5rem; background: rgba(0,0,0,0.25); border-radius: 4px; padding: 0.35rem 0.5rem; margin: 0.35rem 0; }
  .cmd code { font-size: 0.78rem; overflow-x: auto; white-space: pre; flex: 1; }
  .finding-actions { display: flex; gap: 0.5rem; margin-top: 0.35rem; }

  button.ghost { background: transparent; border: 1px solid var(--border-bronze-accent); color: var(--color-bronze-bright); }

  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.3rem 0.4rem; border-bottom: 1px solid var(--border-bronze-subtle); }
  .mono { font-family: ui-monospace, monospace; }
  .os { color: var(--color-ash); max-width: 12rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .dot { display: inline-block; width: 0.5rem; height: 0.5rem; border-radius: 50%; }
  .dot.up { background: var(--color-success); }
  .dot.down { background: var(--color-danger); }

  .activity { list-style: none; margin: 0; padding: 0; font-size: 0.8rem; max-height: 30rem; overflow-y: auto; }
  .activity li { padding: 0.25rem 0; border-bottom: 1px solid var(--border-bronze-subtle); }
  .activity .ts { color: var(--color-ash); margin-right: 0.4rem; font-variant-numeric: tabular-nums; }
</style>
