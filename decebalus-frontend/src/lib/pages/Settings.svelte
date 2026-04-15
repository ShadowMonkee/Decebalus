<script lang="ts">
  import { onMount } from 'svelte';
  import { getConfig, saveConfig, syncCves } from '../api';

  let settings = {
    device_name: 'decebalus-01',
    log_level:   'info',
  };

  let error = '';
  let success = '';
  let loading = true;
  let saving = false;
  let syncing = false;

  onMount(async () => {
    try {
      const config = await getConfig();
      if (config.settings && typeof config.settings === 'object') {
        settings = { ...settings, ...config.settings };
      }
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  });

  async function handleSyncCves() {
    syncing = true;
    error = '';
    success = '';
    try {
      const job = await syncCves();
      success = `CVE sync job queued (ID: ${job.id.slice(0, 8)}…) — check Dashboard or Logs for progress.`;
    } catch (e: any) {
      error = e.message;
    } finally {
      syncing = false;
    }
  }

  async function handleSave() {
    saving = true;
    error = '';
    success = '';
    try {
      await saveConfig(settings);
      success = 'Settings saved.';
    } catch (e: any) {
      error = e.message;
    } finally {
      saving = false;
    }
  }
</script>

<hgroup>
  <h1>Settings</h1>
  <p>Configure Decebalus</p>
</hgroup>

{#if loading}
  <p aria-busy="true">Loading settings…</p>
{:else}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if success}<p class="success" role="status">{success}</p>{/if}

  <article>
    <header><strong>General</strong></header>

    <div class="field">
      <label for="device_name">Device Name</label>
      <input id="device_name" type="text" bind:value={settings.device_name}
             autocomplete="off" spellcheck="false" />
      <small class="helper">Identifies this device on the network.</small>
    </div>

    <div class="field">
      <label for="log_level">Log Level</label>
      <select id="log_level" bind:value={settings.log_level}>
        <option value="debug">Debug</option>
        <option value="info">Info</option>
        <option value="warn">Warning</option>
        <option value="error">Error</option>
      </select>
      <small class="helper">Controls verbosity of system logs.</small>
    </div>

    <footer class="form-footer">
      <button on:click={handleSave} disabled={saving} aria-busy={saving}>
        {saving ? 'Saving…' : 'Save Settings'}
      </button>
    </footer>
  </article>

  <article>
    <header><strong>Vulnerability Database</strong></header>

    <p class="section-desc">
      Enrich discovered CVEs with metadata from the National Vulnerability Database (NVD).
      This runs automatically after each nmap scan; use this button to trigger a manual sync.
    </p>

    <footer class="form-footer">
      <button class="outline" on:click={handleSyncCves} disabled={syncing} aria-busy={syncing}>
        {syncing ? 'Syncing…' : 'Sync CVE Database'}
      </button>
    </footer>
  </article>
{/if}

<style>
  .field {
    margin-bottom: 1.25rem;
  }

  .field label {
    display: block;
    margin-bottom: 0.3rem;
    font-size: 0.9rem;
    font-weight: 500;
  }

  .field input,
  .field select {
    margin-bottom: 0.2rem;
  }

  .helper {
    color: var(--color-ash);
    font-size: 0.8rem;
    display: block;
  }

  .form-footer {
    display: flex;
    justify-content: flex-end;
    margin-top: 0.5rem;
    padding-top: 1rem;
    border-top: 1px solid var(--pico-muted-border-color);
  }

  .form-footer button {
    width: auto;
    min-width: 140px;
  }

  .section-desc {
    font-size: 0.875rem;
    color: var(--color-ash-light);
    margin-bottom: 0;
  }
</style>
