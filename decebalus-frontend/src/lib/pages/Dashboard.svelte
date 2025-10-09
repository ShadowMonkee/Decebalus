<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { connectWebSocket, closeWebSocket } from '../stores/websocketStore';

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
  let isReady = false;

  let wsInstance: any = null;

  onMount(() => {
    wsInstance = connectWebSocket();

    wsInstance.onMessage = (data: any) => {
      switch (data.type) {
        case 'system_stats':
          systemStats = data.stats;
          break;
        case 'activity':
          recentActivity = [data, ...recentActivity].slice(0, 10);
          handleActivity(data);
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
    isReady = true;
  });

  onDestroy(() => {
    wsInstance = null;
  });

  function handleActivity(data: any) {
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
</script>

{#if isReady}
<div class="space-y-6">
  <!-- Header -->
  <div class="flex items-center justify-between">
    <div>
      <h1 class="text-3xl font-bold text-bronze text-glow">Dashboard</h1>
      <p class="text-ash mt-2">Monitor your Dacian warrior's activities</p>
    </div>
    <div class="text-6xl">{wolfEmoji}</div>
  </div>

  <!-- Stats Grid -->
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
    <!-- CPU Usage -->
    <div class="card">
      <div class="flex items-center justify-between mb-2">
        <span class="text-ash-light font-medium">CPU Usage</span>
        <span class="text-2xl">🔥</span>
      </div>
      <div class="text-3xl font-bold text-bronze">{systemStats.cpu.toFixed(1)}%</div>
      <div class="progress-bar mt-3">
        <div class="progress-fill" style="width: {systemStats.cpu}%"></div>
      </div>
    </div>

    <!-- Memory Usage -->
    <div class="card">
      <div class="flex items-center justify-between mb-2">
        <span class="text-ash-light font-medium">Memory</span>
        <span class="text-2xl">💾</span>
      </div>
      <div class="text-3xl font-bold text-bronze">{systemStats.memory.toFixed(1)}%</div>
      <div class="progress-bar mt-3">
        <div class="progress-fill" style="width: {systemStats.memory}%"></div>
      </div>
    </div>

    <!-- Temperature -->
    <div class="card">
      <div class="flex items-center justify-between mb-2">
        <span class="text-ash-light font-medium">Temperature</span>
        <span class="text-2xl">🌡️</span>
      </div>
      <div class="text-3xl font-bold text-bronze">{systemStats.temperature.toFixed(1)}°C</div>
      <div class="progress-bar mt-3">
        <div class="progress-fill" style="width: {Math.min(100, (systemStats.temperature / 100) * 100)}%"></div>
      </div>
    </div>

    <!-- Uptime -->
    <div class="card">
      <div class="flex items-center justify-between mb-2">
        <span class="text-ash-light font-medium">Uptime</span>
        <span class="text-2xl">⏱️</span>
      </div>
      <div class="text-3xl font-bold text-bronze">{formatUptime(systemStats.uptime)}</div>
      <div class="text-ash-light text-sm mt-2">System running</div>
    </div>
  </div>

  <!-- Activity Overview -->
  <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
    <!-- Active Scans -->
    <div class="card text-center">
      <div class="text-5xl mb-3">🔍</div>
      <div class="text-4xl font-bold text-bronze mb-2">{activeScans}</div>
      <div class="text-ash-light">Active Scans</div>
    </div>

    <!-- Discovered Targets -->
    <div class="card text-center">
      <div class="text-5xl mb-3">🎯</div>
      <div class="text-4xl font-bold text-bronze mb-2">{discoveredTargets}</div>
      <div class="text-ash-light">Discovered Targets</div>
    </div>

    <!-- Wolf State -->
    <div class="card text-center">
      <div class="text-5xl mb-3">{wolfEmoji}</div>
      <div class="text-2xl font-bold text-bronze mb-2 capitalize">{wolfState}</div>
      <div class="text-ash-light">Current State</div>
    </div>
  </div>

  <!-- Recent Activity -->
  <div class="card">
    <div class="flex items-center justify-between mb-4">
      <h2 class="text-xl font-bold text-bronze">Recent Activity</h2>
      <span class="text-2xl">📜</span>
    </div>

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
{:else}
<div class="flex items-center justify-center min-h-[60vh]">
  <div class="text-center">
    <div class="text-6xl mb-4 animate-pulse">🐺</div>
    <p class="text-ash-light text-lg">Loading dashboard...</p>
  </div>
</div>
{/if}