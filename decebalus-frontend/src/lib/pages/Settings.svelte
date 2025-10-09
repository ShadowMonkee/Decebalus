<script>
  let settings = {
    deviceName: 'decebalus-01',
    autoScan: false,
    scanInterval: 300,
    saveResults: true,
    dangerMode: false,
    logLevel: 'info'
  };
  
  function saveSettings() {
    // TODO: Send to backend
    console.log('Saving settings:', settings);
  }
</script>

<div class="space-y-6">
  <div>
    <h1 class="text-3xl font-bold text-bronze text-glow">Settings</h1>
    <p class="text-ash mt-2">Configure Decebalus to suit your needs</p>
  </div>
  
  <!-- General Settings -->
  <div class="card">
    <h2 class="text-xl font-bold text-bronze mb-4">General</h2>
    <div class="space-y-4">
      <div>
        <label class="block text-ash-light mb-2">Device Name</label>
        <input type="text" bind:value={settings.deviceName} class="input" />
      </div>
      
      <div class="flex items-center justify-between">
        <div>
          <label class="block text-ash-light">Auto Scan</label>
          <p class="text-ash text-sm">Automatically scan for targets on startup</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.autoScan} class="sr-only peer" />
          <div class="w-11 h-6 bg-forest-dark peer-checked:bg-bronze rounded-full peer transition-all"></div>
          <div class="absolute left-1 top-1 bg-ash-light w-4 h-4 rounded-full transition-transform peer-checked:translate-x-5"></div>
        </label>
      </div>
      
      <div>
        <label class="block text-ash-light mb-2">Scan Interval (seconds)</label>
        <input type="number" bind:value={settings.scanInterval} min="60" max="3600" class="input" />
      </div>
      
      <div class="flex items-center justify-between">
        <div>
          <label class="block text-ash-light">Save Scan Results</label>
          <p class="text-ash text-sm">Automatically save results to disk</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.saveResults} class="sr-only peer" />
          <div class="w-11 h-6 bg-forest-dark peer-checked:bg-bronze rounded-full peer transition-all"></div>
          <div class="absolute left-1 top-1 bg-ash-light w-4 h-4 rounded-full transition-transform peer-checked:translate-x-5"></div>
        </label>
      </div>
    </div>
  </div>
  
  <!-- Advanced Settings -->
  <div class="card">
    <h2 class="text-xl font-bold text-bronze mb-4">Advanced</h2>
    <div class="space-y-4">
      <div>
        <label class="block text-ash-light mb-2">Log Level</label>
        <select bind:value={settings.logLevel} class="input">
          <option value="debug">Debug</option>
          <option value="info">Info</option>
          <option value="warn">Warning</option>
          <option value="error">Error</option>
        </select>
      </div>
      
      <div class="flex items-center justify-between p-4 bg-danger/10 border border-danger rounded">
        <div>
          <label class="block text-ash-light font-bold">⚠️ Danger Mode</label>
          <p class="text-ash text-sm">Enable experimental and potentially dangerous features</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" bind:checked={settings.dangerMode} class="sr-only peer" />
          <div class="w-11 h-6 bg-forest-dark peer-checked:bg-danger rounded-full peer transition-all"></div>
          <div class="absolute left-1 top-1 bg-ash-light w-4 h-4 rounded-full transition-transform peer-checked:translate-x-5"></div>
        </label>
      </div>
    </div>
  </div>
  
  <!-- Actions -->
  <div class="flex gap-3">
    <button on:click={saveSettings} class="btn-primary">
      Save Settings
    </button>
    <button class="btn-secondary">
      Reset to Defaults
    </button>
  </div>
  
  <!-- System Info -->
  <div class="card">
    <h2 class="text-xl font-bold text-bronze mb-4">About</h2>
    <div class="space-y-2 text-ash">
      <p><strong>Version:</strong> 0.1.0-alpha</p>
      <p><strong>Device:</strong> Raspberry Pi Zero 2 W</p>
      <p><strong>Author:</strong> Dacian Warrior</p>
      <p><strong>License:</strong> MIT</p>
      <p class="mt-4">
        <a href="https://github.com/yourusername/decebalus" target="_blank" class="text-bronze hover:underline">
          📖 Documentation
        </a>
        <span class="mx-2">•</span>
        <a href="https://github.com/yourusername/decebalus/issues" target="_blank" class="text-bronze hover:underline">
          🐛 Report Issues
        </a>
      </p>
    </div>
  </div>
</div>