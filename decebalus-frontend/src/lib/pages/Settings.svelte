<script lang="ts">
  import { onMount } from 'svelte';
  import { getConfig, saveConfig, syncCves } from '../api';

  // Defaults mirror the backend's settings::Settings::default().
  let settings = {
    device_name: 'decebalus-01',
    log_level: 'info',
    log_retention_days: 30,
    max_scan_concurrency: 500,
    max_discover_threads: 256,
    port_scan_timeout_ms: 200,
    host_alive_timeout_ms: 500,
    nvd_api_key: '',
    autonomous_enabled: false,
    autonomous_attacks_enabled: false,
    autonomous_interval_secs: 900,
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
      success = 'Settings saved. Changes apply immediately (except worker-thread count, which needs a restart).';
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
      <small class="helper">Identifies this device on the network and the display.</small>
    </div>

    <div class="field">
      <label for="log_level">Log Level</label>
      <select id="log_level" bind:value={settings.log_level}>
        <option value="debug">Debug</option>
        <option value="info">Info</option>
        <option value="warn">Warning</option>
        <option value="error">Error</option>
      </select>
      <small class="helper">Controls verbosity of system logs. Applied live on save.</small>
    </div>

    <div class="field">
      <label for="log_retention_days">Log Retention (days)</label>
      <input id="log_retention_days" type="number" min="1" max="365"
             bind:value={settings.log_retention_days} />
      <small class="helper">Logs older than this are purged on startup.</small>
    </div>
  </article>

  <article>
    <header><strong>Scanning</strong></header>

    <div class="grid">
      <div class="field">
        <label for="max_scan_concurrency">Port-scan concurrency</label>
        <input id="max_scan_concurrency" type="number" min="1" max="5000"
               bind:value={settings.max_scan_concurrency} />
        <small class="helper">Simultaneous TCP connects per host scan.</small>
      </div>

      <div class="field">
        <label for="max_discover_threads">Discovery concurrency</label>
        <input id="max_discover_threads" type="number" min="1" max="2048"
               bind:value={settings.max_discover_threads} />
        <small class="helper">Simultaneous probes during the TCP discovery fallback.</small>
      </div>

      <div class="field">
        <label for="port_scan_timeout_ms">Port-scan timeout (ms)</label>
        <input id="port_scan_timeout_ms" type="number" min="50" max="10000"
               bind:value={settings.port_scan_timeout_ms} />
        <small class="helper">Per-port connect timeout. Raise on slow/distant networks.</small>
      </div>

      <div class="field">
        <label for="host_alive_timeout_ms">Host-alive timeout (ms)</label>
        <input id="host_alive_timeout_ms" type="number" min="50" max="10000"
               bind:value={settings.host_alive_timeout_ms} />
        <small class="helper">Per-port timeout for the discovery liveness probe.</small>
      </div>
    </div>
  </article>

  <article>
    <header><strong>Autonomous Operation</strong></header>
    <p class="section-desc">
      When enabled, Decebalus continuously discovers the local network, scans new hosts, and
      enriches CVEs on a loop — no manual jobs needed.
    </p>

    <div class="field">
      <label class="switch-row">
        <input type="checkbox" role="switch" bind:checked={settings.autonomous_enabled} />
        Enable autonomous mode
      </label>
      <small class="helper">Recon only (discover → scan → nmap → CVE) unless attacks are enabled below.</small>
    </div>

    <div class="field">
      <label class="switch-row">
        <input type="checkbox" role="switch" bind:checked={settings.autonomous_attacks_enabled}
               disabled={!settings.autonomous_enabled} />
        Allow autonomous brute-force attacks
      </label>
      <small class="helper danger-helper">
        ⚠ Off by default. When on, the loop runs brute-force attacks against discovered hosts.
        Only enable on networks you are authorized to test.
      </small>
    </div>

    <div class="field">
      <label for="autonomous_interval_secs">Cycle interval (seconds)</label>
      <input id="autonomous_interval_secs" type="number" min="30" max="86400"
             bind:value={settings.autonomous_interval_secs} disabled={!settings.autonomous_enabled} />
      <small class="helper">Pause between autonomous cycles.</small>
    </div>
  </article>

  <article>
    <header><strong>Vulnerability Database</strong></header>

    <p class="section-desc">
      Enrich discovered CVEs with metadata from the National Vulnerability Database (NVD).
      Runs automatically after each nmap scan; use the button for a manual sync.
    </p>

    <div class="field">
      <label for="nvd_api_key">NVD API Key (optional)</label>
      <input id="nvd_api_key" type="text" bind:value={settings.nvd_api_key}
             autocomplete="off" spellcheck="false"
             placeholder="Speeds up enrichment (~50 req/30s vs ~5)" />
      <small class="helper">Request a free key at nvd.nist.gov/developers/request-an-api-key.</small>
    </div>

    <footer class="form-footer">
      <button class="outline" on:click={handleSyncCves} disabled={syncing} aria-busy={syncing}>
        {syncing ? 'Syncing…' : 'Sync CVE Database'}
      </button>
    </footer>
  </article>

  <article>
    <footer class="form-footer">
      <button on:click={handleSave} disabled={saving} aria-busy={saving}>
        {saving ? 'Saving…' : 'Save Settings'}
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

  .switch-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
  }

  .switch-row input {
    margin: 0;
    width: auto;
  }

  .helper {
    color: var(--color-ash);
    font-size: 0.8rem;
    display: block;
  }

  .danger-helper {
    color: var(--pico-del-color, #b3261e);
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
    margin-bottom: 1rem;
  }
</style>
