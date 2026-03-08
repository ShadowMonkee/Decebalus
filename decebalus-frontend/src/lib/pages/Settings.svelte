<script lang="ts">
  import { onMount } from 'svelte';
  import { getConfig, saveConfig } from '../api';

  // Known config fields surfaced as a typed form.
  // The backend Config stores arbitrary key-value JSON, so we merge defaults with whatever exists.
  let settings = {
    device_name:   'decebalus-01',
    log_level:     'info',
  };

  let error = '';
  let success = '';
  let loading = true;
  let saving = false;

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
  <p aria-busy="true">Loading settings...</p>
{:else}
  {#if error}<p class="error">{error}</p>{/if}
  {#if success}<p class="success">{success}</p>{/if}

  <article>
    <header><strong>General</strong></header>

    <label for="device_name">Device Name</label>
    <input id="device_name" type="text" bind:value={settings.device_name} />

    <label for="log_level">Log Level</label>
    <select id="log_level" bind:value={settings.log_level}>
      <option value="debug">Debug</option>
      <option value="info">Info</option>
      <option value="warn">Warning</option>
      <option value="error">Error</option>
    </select>
  </article>

  <button on:click={handleSave} disabled={saving} aria-busy={saving}>
    {saving ? 'Saving...' : 'Save Settings'}
  </button>
{/if}
