<script lang="ts">
  import { onMount } from 'svelte';
  import {
    getEngagements, createEngagement, activateEngagement, getCredentials,
    type Engagement, type Credential,
  } from '../api';

  let engagements: Engagement[] = [];
  let credentials: Credential[] = [];
  let error = '';
  let ok = '';
  let busy = false;

  // Create form
  let name = '';
  let scope = '';
  let domain = '';
  let dc_ip = '';
  let username = '';
  let password = '';

  async function refresh() {
    try {
      [engagements, credentials] = await Promise.all([getEngagements(), getCredentials()]);
      error = '';
    } catch (e: any) {
      error = e.message ?? 'Failed to load engagements';
    }
  }

  async function create() {
    busy = true; ok = ''; error = '';
    try {
      const scope_cidrs = scope.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
      await createEngagement({
        name,
        scope_cidrs,
        domain: domain || undefined,
        dc_ip: dc_ip || undefined,
        username: username || undefined,
        password: password || undefined,
      });
      ok = `Engagement “${name}” created and activated.`;
      name = scope = domain = dc_ip = username = password = '';
      await refresh();
    } catch (e: any) {
      error = e.message ?? 'Failed to create engagement';
    } finally {
      busy = false;
    }
  }

  async function activate(id: string) {
    try { await activateEngagement(id); await refresh(); }
    catch (e: any) { error = e.message; }
  }

  const privBadge = (p: string) =>
    p === 'da' || p === 'admin' ? 'badge-danger' : p === 'user' ? 'badge-info' : 'badge-neutral';

  onMount(refresh);
</script>

<h2>Engagement</h2>
<p class="muted">Define scope (CIDRs) and an optional starting credential. The active engagement drives scope-lock and owns all findings, facts, and credentials.</p>

{#if error}<p class="error">{error}</p>{/if}
{#if ok}<p class="success">{ok}</p>{/if}

<div class="cols">
  <section class="panel">
    <h3>New engagement</h3>
    <form on:submit|preventDefault={create}>
      <label>Name<input bind:value={name} placeholder="Acme internal" required /></label>
      <label>Scope CIDRs<textarea bind:value={scope} rows="2" placeholder="10.0.0.0/24, 10.0.1.0/24"></textarea></label>
      <div class="row">
        <label>Domain<input bind:value={domain} placeholder="acme.local" /></label>
        <label>DC IP<input bind:value={dc_ip} placeholder="10.0.0.5" /></label>
      </div>
      <fieldset>
        <legend>Starting credential (optional)</legend>
        <div class="row">
          <label>Username<input bind:value={username} placeholder="jdoe" /></label>
          <label>Password<input bind:value={password} type="password" /></label>
        </div>
      </fieldset>
      <button type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create & activate'}</button>
    </form>
  </section>

  <section class="panel">
    <h3>Engagements <span class="count">{engagements.length}</span></h3>
    {#if engagements.length === 0}
      <div class="empty-state">No engagements yet.</div>
    {:else}
      <ul class="eng-list">
        {#each engagements as e (e.id)}
          <li>
            <div>
              <strong>{e.name}</strong>
              {#if e.status === 'active'}<span class="badge badge-success">active</span>{/if}
              <div class="meta">{e.scope_cidrs.join(', ') || 'no scope'}{e.domain ? ` · ${e.domain}` : ''}</div>
            </div>
            {#if e.status !== 'active'}
              <button class="sm ghost" on:click={() => activate(e.id)}>Activate</button>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </section>
</div>

<section class="panel vault">
  <h3>Credential vault <span class="count">{credentials.length}</span></h3>
  {#if credentials.length === 0}
    <div class="empty-state">No credentials captured yet.</div>
  {:else}
    <div class="table-wrap">
      <table>
        <thead><tr><th>Domain</th><th>Username</th><th>Type</th><th>Priv</th><th>Validated</th><th>Valid on</th></tr></thead>
        <tbody>
          {#each credentials as c (c.id)}
            <tr>
              <td>{c.domain || '—'}</td>
              <td class="mono">{c.username}</td>
              <td>{c.secret_type}</td>
              <td><span class="badge {privBadge(c.privilege)}">{c.privilege}</span></td>
              <td>{#if c.validated}<span class="badge badge-success">yes</span>{:else}<span class="badge badge-neutral">no</span>{/if}</td>
              <td class="mono small">{c.valid_on.join(', ') || '—'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<style>
  .muted { color: var(--color-ash); }
  .cols { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 1rem; }
  @media (max-width: 900px) { .cols { grid-template-columns: 1fr; } }

  .panel { border: 1px solid var(--border-bronze-subtle); border-radius: 8px; padding: 0.85rem 1rem; background: var(--surface-raised); }
  .panel h3 { margin: 0 0 0.75rem; font-size: 0.95rem; display: flex; align-items: center; gap: 0.5rem; }
  .count { color: var(--color-ash); font-weight: 400; font-size: 0.8rem; }
  .vault { margin-top: 1rem; }

  form label { display: block; margin-bottom: 0.6rem; font-size: 0.85rem; }
  form .row { display: flex; gap: 0.6rem; }
  form .row label { flex: 1; }
  input, textarea { width: 100%; }
  fieldset { border: 1px solid var(--border-bronze-subtle); border-radius: 6px; padding: 0.5rem 0.7rem; margin: 0 0 0.7rem; }
  legend { font-size: 0.78rem; color: var(--color-ash); padding: 0 0.3rem; }

  .eng-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.5rem; }
  .eng-list li { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; border-bottom: 1px solid var(--border-bronze-subtle); padding-bottom: 0.5rem; }
  .eng-list .meta { color: var(--color-ash); font-size: 0.8rem; margin-top: 0.2rem; }

  button.ghost { background: transparent; border: 1px solid var(--border-bronze-accent); color: var(--color-bronze-bright); }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.3rem 0.4rem; border-bottom: 1px solid var(--border-bronze-subtle); }
  .mono { font-family: ui-monospace, monospace; }
  .small { font-size: 0.78rem; color: var(--color-ash); }
</style>
