<script lang="ts">
  import { Router, Route } from 'svelte-routing';
  import { websocket, connectWebSocket, closeWebSocket } from './lib/stores/websocketStore';
  import { onMount } from 'svelte';
  import { derived } from 'svelte/store';

  // Components
  import Navbar from './lib/components/Navbar.svelte';


  // DASHBOARD THINGS
  // System stats type
  interface SystemStats {
    cpu: number;
    memory: number;
    temperature: number;
    uptime: number;
  }

  // Activity type
  interface Activity {
    type: string;
    activityType?: 'scan_started' | 'scan_completed' | 'attack_started' | 'attack_completed';
    message: string;
    timestamp: number;
  }

  let systemStats: SystemStats = {
    cpu: 0,
    memory: 0,
    temperature: 0,
    uptime: 0
  };

  let recentActivity: Activity[] = [];
  let activeScans = 0;
  let discoveredTargets = 0;
  let wolfState: 'idle' | 'scanning' | 'attacking' = 'idle';
  let isReadyDashboard = true; // TODO: change it to false when we have a connection to the websocket

  let wsInstance: any = null;

  function onMountDashboard() {
    wsInstance = connectWebSocket();

    wsInstance.onMessage = (data: any) => {
      switch (data.type) {
        case 'system_stats':
          systemStats = data.stats;
          break;
        case 'activity':
          recentActivity = [data, ...recentActivity].slice(0, 10);
          handleActivityDashboard(data);
          break;
        case 'target_discovered':
          discoveredTargets++;
          break;
      }
    };

    // Request initial stats
    wsInstance.onOpen?.(() => {
      wsInstance.send({ type: 'get_system_stats' });
    });

    // Mark as ready after mount
    isReadyDashboard = true;
  };

  function handleActivityDashboard(data: any) {
    switch (data.activityType) {
      case 'scan_started':
        wolfState = 'scanning';
        activeScans++;
        break;
      case 'scan_completed':
        wolfState = 'idle';
        activeScans = Math.max(0, activeScans - 1);
        break;
      case 'attack_started':
        wolfState = 'attacking';
        break;
      case 'attack_completed':
        wolfState = 'idle';
        break;
    }
  }

  function formatUptime(seconds: number) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${minutes}m`;
  }

  function formatTime(timestamp: number) {
    return new Date(timestamp).toLocaleTimeString();
  }

  function getActivityIcon(type: string) {
    const icons: Record<string, string> = {
      scan_started: '🔍',
      scan_completed: '✅',
      attack_started: '⚔️',
      attack_completed: '🎯',
      target_discovered: '🎯',
      plugin_loaded: '🔌',
      error: '❌'
    };
    return icons[type] || '📡';
  }

  function getWolfEmoji() {
    switch (wolfState) {
      case 'scanning':
        return '🐺👁️';
      case 'attacking':
        return '🐺⚔️';
      default:
        return '🐺💤';
    }
  }

  $: wolfEmoji = getWolfEmoji();

  // END DASHBOARD

  // RECONNAISSANCE THINGS

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
  function onMountReconnaissance() {
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
  };

  // END RECONNAISSANCE

  // BEGIN ATTACKS
  // Placeholder for attacks page
  let attacks = [
    { id: 1, name: 'WiFi Deauthentication', category: 'WiFi', icon: '📡', status: 'ready' },
    { id: 2, name: 'Evil Twin AP', category: 'WiFi', icon: '👥', status: 'ready' },
    { id: 3, name: 'DNS Spoofing', category: 'Network', icon: '🌐', status: 'ready' },
    { id: 4, name: 'ARP Poisoning', category: 'Network', icon: '🎯', status: 'ready' },
  ];
  // END ATTACKS


  // BEGIN SETTINGS
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
  // End Settings


  // Derived store to compute connection status from WebSocket state
 type ConnectionStatus = 'connected' | 'connecting' | 'disconnected';

  const connectionStatus = derived(websocket, ($ws): ConnectionStatus => {
    if (!$ws) return 'disconnected';
    if ($ws.readyState === WebSocket.OPEN) return 'connected';
    if ($ws.readyState === WebSocket.CONNECTING) return 'connecting';
    return 'disconnected';
  });

  onMount(() => {
    connectWebSocket();
    return () => closeWebSocket();
  });
</script>

<Router url="">
    <Navbar connectionStatus={$connectionStatus} />

    <main class="flex-1 container mx-auto px-4 py-6 max-w-7xl pt-16">
      <Route path="/">
        <div class="space-y-6">
          <!-- Header -->
          <header class="flex items-center justify-between mb-4">
            <div>
              <h1 class="text-3xl font-bold text-bronze text-glow">Dashboard</h1>
              <p class="text-ash mt-2">Monitor your Dacian warrior's activities</p>
            </div>
            <div class="text-6xl">{wolfEmoji}</div>
          </header>

          <!-- Stats Grid -->
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <!-- CPU Usage -->
            <div class="card">
                <header class="flex items-center justify-between mb-2">
                  <span class="text-ash-light font-medium">CPU Usage</span>
                  <span class="text-2xl">🔥</span>
                </header>
                <div class="text-3xl font-bold text-bronze">25.0%</div>
                <div class="progress-bar mt-3">
                  <div class="progress-fill" style="width: 25%;"></div>
                </div>
              </div>


            <!-- Memory Usage -->
            <div class="card">
              <header class="flex items-center justify-between mb-2">
                <span class="text-ash-light font-medium">Memory</span>
                <span class="text-2xl">💾</span>
              </header>
              <div class="text-3xl font-bold text-bronze">{systemStats.memory.toFixed(1)}%</div>
              <div class="progress-bar mt-3">
                <div class="progress-fill" style={`width: ${systemStats.memory}%`}></div>
              </div>
            </div>

            <!-- Temperature -->
            <div class="card">
              <header class="flex items-center justify-between mb-2">
                <span class="text-ash-light font-medium">Temperature</span>
                <span class="text-2xl">🌡️</span>
              </header>
              <div class="text-3xl font-bold text-bronze">{systemStats.temperature.toFixed(1)}°C</div>
              <div class="progress-bar mt-3">
                <div class="progress-fill" style={`width: ${Math.min(100, (systemStats.temperature / 100) * 100)}%`}></div>
              </div>
            </div>

            <!-- Uptime -->
            <div class="card">
              <header class="flex items-center justify-between mb-2">
                <span class="text-ash-light font-medium">Uptime</span>
                <span class="text-2xl">⏱️</span>
              </header>
              <div class="text-3xl font-bold text-bronze">{formatUptime(systemStats.uptime)}</div>
              <div class="text-ash-light text-sm mt-2">System running</div>
            </div>
          </div>

          <!-- Activity Overview -->
          <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <!-- Active Scans -->
            <div class="card text-center">
              <span class="text-5xl mb-3">🔍</span>
              <div class="text-4xl font-bold text-bronze mb-2">{activeScans}</div>
              <div class="text-ash-light">Active Scans</div>
            </div>

            <!-- Discovered Targets -->
            <div class="card text-center">
              <span class="text-5xl mb-3">🎯</span>
              <div class="text-4xl font-bold text-bronze mb-2">{discoveredTargets}</div>
              <div class="text-ash-light">Discovered Targets</div>
            </div>

            <!-- Wolf State -->
            <div class="card text-center">
              <span class="text-5xl mb-3">{wolfEmoji}</span>
              <div class="text-2xl font-bold text-bronze mb-2 capitalize">{wolfState}</div>
              <div class="text-ash-light">Current State</div>
            </div>
          </div>

          <!-- Recent Activity -->
          <div class="card">
            <header class="flex items-center justify-between mb-4">
              <h2 class="text-xl font-bold text-bronze">Recent Activity</h2>
              <span class="text-2xl">📜</span>
            </header>

            {#if recentActivity.length === 0}
              <p class="text-ash text-center py-8">No recent activity</p>
            {:else}
              <div class="space-y-2">
                {#each recentActivity as activity}
                  <div class="card-hover flex items-center justify-between fade-in">
                    <div class="flex items-center gap-3">
                      <span class="text-2xl">{getActivityIcon(activity.activityType || activity.type)}</span>
                      <div>
                        <p class="text-ash-light font-medium">{activity.message}</p>
                        <p class="text-ash text-sm">{formatTime(activity.timestamp)}</p>
                      </div>
                    </div>
                    {#if activity.activityType}
                      <span class="badge-info capitalize">{activity.activityType.replace('_', ' ')}</span>
                    {/if}
                  </div>
                {/each}
              </div>
            {/if}
          </div>
        </div>
      </Route>
      <Route path="/recon">
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
      </Route>
      <Route path="/attacks">
        <div class="space-y-6">
          <div>
            <h1 class="text-3xl font-bold text-bronze text-glow">Attack Modules</h1>
            <p class="text-ash mt-2">Launch attacks against discovered targets</p>
          </div>
          
          <div class="card">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              {#each attacks as attack}
                <div class="card-hover">
                  <div class="flex items-center justify-between">
                    <div class="flex items-center gap-3">
                      <span class="text-3xl">{attack.icon}</span>
                      <div>
                        <h3 class="text-ash-light font-bold">{attack.name}</h3>
                        <p class="text-ash text-sm">{attack.category}</p>
                      </div>
                    </div>
                    <button class="btn-primary">Launch</button>
                  </div>
                </div>
              {/each}
            </div>
          </div>
          
          <div class="card">
            <h3 class="text-lg font-bold text-bronze mb-4">⚠️ Disclaimer</h3>
            <p class="text-ash text-sm">
              These attack modules are for educational and authorized penetration testing purposes only. 
              Unauthorized access to computer systems is illegal. Always ensure you have explicit permission 
              before conducting any security assessments.
            </p>
          </div>
        </div>

      </Route>
      <Route path="/plugins">
        <div class="space-y-6">
          <div>
            <h1 class="text-3xl font-bold text-bronze text-glow">Attack Modules</h1>
            <p class="text-ash mt-2">Launch attacks against discovered targets</p>
          </div>
        </div>
      </Route>
      <Route path="/settings">
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
      </Route>
      <Route path="*">
        <p class="text-red-500">No route matched!</p>
      </Route>
    </main>
  <footer class="border-t border-bronze/20 py-4 text-center text-ash text-sm">
    <p>
      Decebalus v0.1.0 -
      <!-- <span class="text-bronze">Dacian Warrior</span> -->
      | Built with 🐺 by the community
    </p>
  </footer>
</Router>

<style>
  :global(body) {
    margin: 0;
    padding: 0;
  }
</style>
