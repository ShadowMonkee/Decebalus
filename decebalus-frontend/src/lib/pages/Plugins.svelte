<script lang="ts">
  import { onMount } from 'svelte';
  import { getModules, type ModuleMeta } from '../api';

  let modules: ModuleMeta[] = [];
  let selected: ModuleMeta | null = null;
  let loading = true;
  let error = '';

  onMount(async () => {
    try {
      modules = await getModules();
      selected = modules[0] ?? null;
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  });

  const categoryLabel: Record<string, string> = {
    attack: 'Attack',
    exfil: 'Exfiltration',
    enum: 'Enumeration',
    ad: 'Active Directory',
    scan: 'Scan',
  };
  const categoryClass: Record<string, string> = {
    attack: 'badge-danger',
    exfil: 'badge-warn',
    enum: 'badge-info',
    ad: 'badge-neutral',
    scan: 'badge-info',
  };
  const CATEGORY_ORDER = ['attack', 'exfil', 'enum', 'ad', 'scan'];

  // Modules the Attacks page has a launch form for today. Everything else is
  // dispatched by the autonomous engine / rule engine or created via the API.
  const ATTACKS_PAGE_TYPES = new Set([
    'ssh-brute', 'ftp-brute', 'smb-brute', 'rdp-brute', 'file-steal',
  ]);

  // Group modules by category in a stable order for the left-hand list.
  $: groups = (() => {
    const seen = new Set<string>();
    const ordered = CATEGORY_ORDER
      .map((cat) => ({ cat, items: modules.filter((m) => m.category === cat) }))
      .filter((g) => g.items.length);
    ordered.forEach((g) => seen.add(g.cat));
    // Any categories we didn't anticipate still show up, appended at the end.
    const extras = [...new Set(modules.map((m) => m.category))].filter((c) => !seen.has(c));
    return [
      ...ordered,
      ...extras.map((cat) => ({ cat, items: modules.filter((m) => m.category === cat) })),
    ];
  })();

  function cat(c: string) { return categoryLabel[c] ?? c; }
  function catClass(c: string) { return categoryClass[c] ?? 'badge-neutral'; }

  function safetyLabel(s?: string): { text: string; cls: string } | null {
    if (s === 'read_only') return { text: 'Read-only', cls: 'badge-success' };
    if (s === 'risky') return { text: 'Risky', cls: 'badge-danger' };
    return s ? { text: s, cls: 'badge-neutral' } : null;
  }

  function isUrl(s: string): boolean {
    return /^https?:\/\//i.test(s);
  }
</script>

<hgroup>
  <h1>Modules</h1>
  <p>Every attack, exfiltration, enumeration and Active Directory module registered in Decebalus. Pick one to see how it works, what it needs, and why.</p>
</hgroup>

{#if loading}
  <p aria-busy="true">Loading modules…</p>
{:else if error}
  <p class="error" role="alert">{error}</p>
{:else if modules.length === 0}
  <p>No modules registered.</p>
{:else}
  <div class="layout">
    <!-- Master: list on the left -->
    <nav class="list" aria-label="Modules">
      {#each groups as g}
        <p class="group-head">{cat(g.cat)}</p>
        {#each g.items as m}
          <button
            type="button"
            class="list-item"
            class:active={selected?.job_type === m.job_type}
            on:click={() => (selected = m)}
            aria-current={selected?.job_type === m.job_type}
          >
            <span class="item-name">{m.name}</span>
            <span class="badge {catClass(m.category)}">{cat(m.category)}</span>
          </button>
        {/each}
      {/each}
    </nav>

    <!-- Detail: on the right -->
    <section class="detail">
      {#if selected}
        {@const safety = safetyLabel(selected.safety)}
        <header class="detail-head">
          <div class="title-row">
            <h2>{selected.name}</h2>
            <div class="tags">
              <span class="badge {catClass(selected.category)}">{cat(selected.category)}</span>
              {#if safety}<span class="badge {safety.cls}">{safety.text}</span>{/if}
              {#if selected.requires_cred}<span class="badge badge-neutral">Needs credential</span>{/if}
            </div>
          </div>
          <p class="lede">{selected.description}</p>
          <p class="availability">
            {#if ATTACKS_PAGE_TYPES.has(selected.job_type)}
              ▶ Launch this module from the <strong>Attacks</strong> page.
            {:else}
              ▶ Run automatically by the autonomous engine, or create a job via the API
              (<code>POST /api/jobs</code>, job type <code>{selected.job_type}</code>).
            {/if}
          </p>
        </header>

        {#if selected.how_it_works}
          <div class="block">
            <h3>How it works</h3>
            <p>{selected.how_it_works}</p>
          </div>
        {/if}

        {#if selected.why_it_works}
          <div class="block">
            <h3>Why it works</h3>
            <p>{selected.why_it_works}</p>
          </div>
        {/if}

        {#if selected.example_command}
          <div class="block">
            <h3>Underlying command</h3>
            <pre class="cmd">{selected.example_command}</pre>
          </div>
        {/if}

        <div class="block">
          <h3>Ports</h3>
          <dl class="facts">
            <div><dt>Default port</dt><dd>{selected.default_port ?? '—'}</dd></div>
            <div><dt>Relevant for open ports</dt><dd>{selected.trigger_ports.length ? selected.trigger_ports.join(', ') : '—'}</dd></div>
          </dl>
        </div>

        <div class="block">
          <h3>Configuration</h3>
          <dl class="facts">
            <div><dt>Job type</dt><dd><code>{selected.job_type}</code></dd></div>
            <div><dt>Required</dt><dd>{selected.required_config.length ? selected.required_config.join(', ') : '—'}</dd></div>
            <div><dt>Optional</dt><dd>{selected.optional_config.length ? selected.optional_config.join(', ') : '—'}</dd></div>
            {#if selected.produces_facts && selected.produces_facts.length}
              <div><dt>Produces</dt><dd>{selected.produces_facts.join(', ')}</dd></div>
            {/if}
            {#if selected.opsec_noise}
              <div><dt>OPSEC noise</dt><dd>{selected.opsec_noise}</dd></div>
            {/if}
          </dl>
        </div>

        <div class="block">
          <h3>Required tools</h3>
          {#if selected.requires_tools && selected.requires_tools.length}
            <ul class="tools">
              {#each selected.requires_tools as t}
                <li>
                  <div class="tool-top">
                    <strong>{t.name}</strong>
                    <code class="tool-bin">{t.binary}</code>
                    <span class="tool-ver">{t.version}</span>
                  </div>
                  <code class="tool-install">{t.install}</code>
                </li>
              {/each}
            </ul>
          {:else}
            <p class="muted">None — this module is fully built in (no external binary required).</p>
          {/if}
        </div>

        {#if selected.references && selected.references.length}
          <div class="block">
            <h3>References</h3>
            <ul class="refs">
              {#each selected.references as r}
                <li>
                  {#if isUrl(r)}<a href={r} target="_blank" rel="noopener noreferrer">{r}</a>
                  {:else}<span class="muted">{r}</span>{/if}
                </li>
              {/each}
            </ul>
          </div>
        {/if}
      {:else}
        <p class="muted">Select a module from the list.</p>
      {/if}
    </section>
  </div>
{/if}

<style>
  .layout {
    display: grid;
    grid-template-columns: minmax(230px, 300px) 1fr;
    gap: 1.5rem;
    align-items: start;
  }

  /* ── Master list ── */
  .list {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    position: sticky;
    top: calc(var(--nav-height) + 1rem);
    max-height: calc(100vh - var(--nav-height) - 2rem);
    overflow-y: auto;
    padding-right: 0.25rem;
  }

  .group-head {
    margin: 0.75rem 0 0.25rem;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--color-ash);
  }
  .group-head:first-child { margin-top: 0; }

  .list-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
    width: 100%;
    text-align: left;
    background: transparent;
    border: 1px solid transparent;
    border-radius: 0.4rem;
    padding: 0.5rem 0.6rem;
    margin: 0;
    color: var(--color-ash-light);
    font-size: 0.9rem;
    line-height: 1.2;
  }
  .list-item:hover { background: var(--surface-raised); }
  .list-item.active {
    background: var(--color-bronze-glow);
    border-color: var(--border-bronze-accent);
    color: #fff;
  }
  .item-name { font-weight: 600; }

  /* ── Detail ── */
  .detail {
    border: 1px solid var(--border-bronze-subtle);
    border-radius: 0.6rem;
    padding: 1.25rem 1.5rem;
    background: var(--surface-raised);
    min-width: 0;
  }

  .detail-head { border-bottom: 1px solid var(--pico-muted-border-color); padding-bottom: 1rem; margin-bottom: 0.5rem; }
  .title-row { display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
  .title-row h2 { margin: 0; }
  .tags { display: flex; gap: 0.4rem; flex-wrap: wrap; }
  .lede { color: var(--color-ash-light); margin: 0.5rem 0 0; }
  .availability {
    margin: 0.75rem 0 0;
    font-size: 0.85rem;
    color: var(--color-bronze-bright);
  }
  .availability code { color: inherit; }

  .block { margin-top: 1.25rem; }
  .block h3 {
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--color-bronze);
    margin: 0 0 0.4rem;
  }
  .block p { margin: 0; color: var(--color-ash-light); line-height: 1.55; }

  .cmd {
    background: rgba(0, 0, 0, 0.35);
    border: 1px solid var(--pico-muted-border-color);
    border-radius: 0.4rem;
    padding: 0.7rem 0.85rem;
    font-size: 0.82rem;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
    margin: 0;
  }

  .facts { display: grid; gap: 0.4rem; margin: 0; font-size: 0.88rem; }
  .facts div { display: flex; justify-content: space-between; gap: 1rem; }
  .facts dt { color: var(--color-ash); }
  .facts dd { margin: 0; text-align: right; color: var(--color-ash-light); }

  .tools { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 0.6rem; }
  .tools li {
    border: 1px solid var(--pico-muted-border-color);
    border-radius: 0.4rem;
    padding: 0.55rem 0.7rem;
  }
  .tool-top { display: flex; align-items: baseline; gap: 0.6rem; flex-wrap: wrap; }
  .tool-bin { font-size: 0.8rem; color: var(--color-bronze-bright); }
  .tool-ver { font-size: 0.8rem; color: var(--color-ash); }
  .tool-install {
    display: block;
    margin-top: 0.35rem;
    font-size: 0.8rem;
    color: var(--color-ash-light);
  }

  .refs { margin: 0; padding-left: 1.1rem; font-size: 0.85rem; }
  .refs li { margin-bottom: 0.2rem; }

  .muted { color: var(--color-ash); font-size: 0.88rem; }

  /* ── Responsive: stack on narrow screens ── */
  @media (max-width: 720px) {
    .layout { grid-template-columns: 1fr; }
    .list { position: static; max-height: none; }
  }
</style>
