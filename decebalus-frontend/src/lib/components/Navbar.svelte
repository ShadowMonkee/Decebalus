<script lang="ts">
  import { Link } from 'svelte-routing';

  const links = [
    { path: '/', label: 'Dashboard' },
    { path: '/recon', label: 'Reconnaissance' },
    { path: '/attacks', label: 'Attacks' },
    { path: '/plugins', label: 'Plugins' },
    { path: '/settings', label: 'Settings' }
  ];

  type ConnectionStatus = 'connected' | 'connecting' | 'disconnected';
  export let connectionStatus: ConnectionStatus = 'disconnected';

  const getStatusColor = (status: ConnectionStatus) => {
    switch (status) {
      case 'connected':
        return 'bg-green-500';
      case 'connecting':
        return 'bg-yellow-500 animate-pulse';
      default:
        return 'bg-red-500';
    }
  };
</script>

<nav class="fixed top-0 left-0 w-full bg-gray-900 text-white h-16 flex items-center px-6 shadow-lg z-50">
  <div class="px-6 py-3 flex items-center justify-between max-w-6xl mx-auto">
    <!-- Links -->
    <div class="flex space-x-6">
      {#each links as { path, label }}
        <Link
          to={path}
          class="nav-link text-sm font-medium transition-colors duration-200"
          getProps={({ isCurrent }) => ({ class: isCurrent ? 'nav-link active' : 'nav-link' })}
        >
          <span>{label}</span>
        </Link>
      {/each}
    </div>

    <!-- Connection indicator -->
    <div class="flex items-center space-x-2">
      <div class={`w-3 h-3 rounded-full ${getStatusColor(connectionStatus)}`}></div>
      <span class="text-sm capitalize">{connectionStatus}</span>
    </div>
  </div>
</nav>
