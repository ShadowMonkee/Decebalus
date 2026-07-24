<script lang="ts">
  import { onMount } from 'svelte';
  import { getModules, type ModuleMeta } from '../api';

  let modules: ModuleMeta[] = [];
  let loading = true;
  let error = '';

  onMount(async () => {
    try {
      modules = await getModules();
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  });

  const categoryLabel: Record<string, string> = {
    attack: 'Attack',
    exfil: 'Exfiltration',
    scan: 'Scan',
  };
  const categoryClass: Record<string, string> = {
    attack: 'badge-danger',
    exfil: 'badge-warn',
    scan: 'badge-info',
  };
</script>

<hgroup>
  <h1>Modules</h1>
  <p>Attack and exploit modules registered in Decebalus. Launch them from the Attacks page.</p>
</hgroup>

{#if loading}
  <p aria-busy="true">Loading modules…</p>
{:else if error}
  <p class="error" role="alert">{error}</p>
{:else if modules.length === 0}
  <p>No modules registered.</p>
{:else}
  <div class="module-grid">
    {#each modules as m}
      <article class="module-card">
        <header class="card-head">
          <strong>{m.name}</strong>
          <span class="badge {categoryClass[m.category] ?? 'badge-neutral'}">
            {categoryLabel[m.category] ?? m.category}
          </span>
        </header>
        <p class="desc">{m.description}</p>
        <dl>
          <div><dt>Job type</dt><dd><code>{m.job_type}</code></dd></div>
          {#if m.default_port !== null}
            <div><dt>Default port</dt><dd>{m.default_port}</dd></div>
          {/if}
          <div><dt>Requires</dt><dd>{m.required_config.join(', ') || '—'}</dd></div>
          {#if m.optional_config.length}
            <div><dt>Optional</dt><dd>{m.optional_config.join(', ')}</dd></div>
          {/if}
          {#if m.trigger_ports.length}
            <div><dt>Suggested for ports</dt><dd>{m.trigger_ports.join(', ')}</dd></div>
          {/if}
        </dl>
      </article>
    {/each}
  </div>
{/if}

<style>
  .module-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 1rem;
  }

  .module-card {
    margin: 0;
  }

  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
  }

  .desc {
    font-size: 0.875rem;
    color: var(--color-ash-light);
  }

  dl {
    display: grid;
    gap: 0.4rem;
    margin: 0;
    font-size: 0.85rem;
  }

  dl div {
    display: flex;
    justify-content: space-between;
    gap: 0.75rem;
  }

  dt {
    color: var(--color-ash);
    font-weight: 500;
  }

  dd {
    margin: 0;
    text-align: right;
  }
</style>
