<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { connectWebSocket } from '../stores/websocketStore';

  // --- Interfaces ---
  interface WifiNetwork {
    ssid?: string;
    bssid: string;
    channel: number;
    signal: number;
    security: string;
  }

  interface NetworkHost {
    ip: string;
    hostname?: string;
    mac?: string;
    ports?: number[];
  }

  interface BluetoothDevice {
    name?: string;
    address: string;
    deviceClass?: string;
  }

  // --- State ---
  let activeTab: 'wifi' | 'network' | 'bluetooth' = 'wifi';
  let scanning = false;
  let scanProgress = 0;
  let scanStatus = '';

  let wifiNetworks: WifiNetwork[] = [];
  let networkHosts: NetworkHost[] = [];
  let bluetoothDevices: BluetoothDevice[] = [];

  let wsInstance: any = null;

  // --- Helpers ---
  function getSignalStrength(signal: number) {
    const percentage = Math.min(100, Math.max(0, (signal + 100) * 2));
    const bars = Math.ceil(percentage / 25);
    return bars;
  }

  function getSecurityBadge(security: string) {
    if (security.includes('WPA3')) return 'badge-success';
    if (security.includes('WPA2')) return 'badge-info';
    if (security.includes('WEP')) return 'badge-danger';
    return 'badge-warning';
  }

  function startScan() {
    scanning = true;
    scanProgress = 0;
    scanStatus = 'Initializing scan...';

    const scanTypes = {
      wifi: 'start_wifi_scan',
      network: 'start_network_scan',
      bluetooth: 'start_bluetooth_scan'
    };

    wsInstance?.send({ type: scanTypes[activeTab] });
  }

  function stopScan() {
    scanning = false;
    wsInstance?.send({ type: 'stop_scan' });
  }

  // --- Lifecycle ---
  onMount(() => {
    // Connect WebSocket
    wsInstance = connectWebSocket();

    // Override onMessage for all incoming events
    wsInstance.onMessage = (data: any) => {
      switch (data.type) {
        case 'wifi_scan_result':
          wifiNetworks = data.networks;
          scanning = false;
          scanProgress = 100;
          break;
        case 'network_scan_result':
          networkHosts = data.hosts;
          scanning = false;
          scanProgress = 100;
          break;
        case 'bluetooth_scan_result':
          bluetoothDevices = data.devices;
          scanning = false;
          scanProgress = 100;
          break;
        case 'scan_progress':
          scanProgress = data.percent;
          scanStatus = data.status;
          break;
      }
    };
  });

  onDestroy(() => {
    wsInstance = null;
  });
</script>

<div class="space-y-6">
  <!-- Header -->
  <div class="flex items-center justify-between">
    <div>
      <h1 class="text-3xl font-bold text-bronze text-glow">Reconnaissance</h1>
      <p class="text-ash mt-2">Scout the battlefield and identify targets</p>
    </div>

    {#if scanning}
      <button on:click={stopScan} class="btn-danger">
        ⏹️ Stop Scan
      </button>
    {:else}
      <button on:click={startScan} class="btn-primary">
        🔍 Start Scan
      </button>
    {/if}
  </div>

  <!-- Scan Progress -->
  {#if scanning}
    <div class="card fade-in">
      <div class="flex items-center gap-4">
        <div class="flex-1">
          <div class="flex justify-between mb-2">
            <span class="text-ash-light font-medium">{scanStatus}</span>
            <span class="text-bronze">{scanProgress}%</span>
          </div>
          <div class="progress-bar">
            <div class="progress-fill" style="width: {scanProgress}%"></div>
          </div>
        </div>
        <div class="text-4xl animate-pulse">🔍</div>
      </div>
    </div>
  {/if}

  <!-- Tabs -->
  <div class="card">
    <div class="flex gap-2 border-b border-bronze/20 pb-2 overflow-x-auto">
      <button
        class="px-4 py-2 rounded transition-colors {activeTab === 'wifi' ? 'bg-bronze text-forest-dark' : 'bg-forest-dark/50 text-ash-light hover:bg-bronze/20'}"
        on:click={() => activeTab = 'wifi'}>
        📡 WiFi Networks ({wifiNetworks.length})
      </button>
      <button
        class="px-4 py-2 rounded transition-colors {activeTab === 'network' ? 'bg-bronze text-forest-dark' : 'bg-forest-dark/50 text-ash-light hover:bg-bronze/20'}"
        on:click={() => activeTab = 'network'}>
        🌐 Network Hosts ({networkHosts.length})
      </button>
      <button
        class="px-4 py-2 rounded transition-colors {activeTab === 'bluetooth' ? 'bg-bronze text-forest-dark' : 'bg-forest-dark/50 text-ash-light hover:bg-bronze/20'}"
        on:click={() => activeTab = 'bluetooth'}>
        🔵 Bluetooth ({bluetoothDevices.length})
      </button>
    </div>

    <div class="mt-4">
      {#if activeTab === 'wifi'}
        {#if wifiNetworks.length === 0}
          <p class="text-ash text-center py-8">No WiFi networks discovered yet.</p>
        {:else}
          {#each wifiNetworks as network}
            <div class="card-hover flex items-center justify-between fade-in">
              <div class="flex-1 flex items-center gap-3">
                <span class="text-2xl">📡</span>
                <div>
                  <h4 class="text-ash-light font-bold">{network.ssid || '(Hidden SSID)'}</h4>
                  <p class="text-ash text-sm mt-1">
                    <span class="mr-3">📍 {network.bssid}</span>
                    <span class="mr-3">📊 Channel {network.channel}</span>
                  </p>
                </div>
              </div>
              <div class="flex items-center gap-4">
                <div class="signal-strength">
                  {#each Array(4) as _, i}
                    <div class="signal-bar {i < getSignalStrength(network.signal) ? 'active' : ''}" style="height: {(i + 1) * 4}px"></div>
                  {/each}
                </div>
                <span class="{getSecurityBadge(network.security)}">{network.security}</span>
                <button class="btn-ghost text-sm">Details</button>
              </div>
            </div>
          {/each}
        {/if}

      {:else if activeTab === 'network'}
        {#if networkHosts.length === 0}
          <p class="text-ash text-center py-8">No network hosts discovered yet.</p>
        {:else}
          {#each networkHosts as host}
            <div class="card-hover flex items-center justify-between fade-in">
              <div class="flex items-center gap-3">
                <span class="text-2xl">🖥️</span>
                <div>
                  <h4 class="text-ash-light font-bold">{host.ip}</h4>
                  <p class="text-ash text-sm mt-1">
                    {#if host.hostname}<span class="mr-3">🏷️ {host.hostname}</span>{/if}
                    {#if host.mac}<span>📇 {host.mac}</span>{/if}
                  </p>
                </div>
              </div>
              <div class="flex items-center gap-2">
                {#if host.ports && host.ports.length > 0}
                  <span class="badge-info">{host.ports.length} ports open</span>
                {/if}
                <button class="btn-ghost text-sm">Details</button>
              </div>
            </div>
          {/each}
        {/if}

      {:else if activeTab === 'bluetooth'}
        {#if bluetoothDevices.length === 0}
          <p class="text-ash text-center py-8">No Bluetooth devices discovered yet.</p>
        {:else}
          {#each bluetoothDevices as device}
            <div class="card-hover flex items-center justify-between fade-in">
              <div class="flex items-center gap-3">
                <span class="text-2xl">🔵</span>
                <div>
                  <h4 class="text-ash-light font-bold">{device.name || 'Unknown Device'}</h4>
                  <p class="text-ash text-sm mt-1">
                    <span class="mr-3">📍 {device.address}</span>
                    {#if device.deviceClass}<span>🏷️ {device.deviceClass}</span>{/if}
                  </p>
                </div>
              </div>
              <button class="btn-ghost text-sm">Details</button>
            </div>
          {/each}
        {/if}
      {/if}
    </div>
  </div>
</div>
