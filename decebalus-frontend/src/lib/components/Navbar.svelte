<script lang="ts">
  import { Link } from 'svelte-routing';
  import { connectionStatus } from '../stores/websocketStore';

  const links = [
    { path: '/', label: 'Dashboard' },
    { path: '/recon', label: 'Reconnaissance' },
    { path: '/attacks', label: 'Attacks' },
    { path: '/plugins', label: 'Plugins' },
    { path: '/settings', label: 'Settings' }
  ];

  type ConnectionStatus = 'connected' | 'connecting' | 'disconnected';

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

  const getStatusText = (status: ConnectionStatus) => {
    switch (status) {
      case 'connected':
        return 'Connected';
      case 'connecting':
        return 'Connecting...';
      default:
        return 'Disconnected';
    }
  };
</script>

<nav class="fixed top-0 left-0 w-full bg-gray-900 text-white h-16 flex items-center px-6 shadow-lg z-50">
  <div class="max-w-6xl mx-auto flex items-center justify-between w-full">
    <!-- Logo/Brand -->
    <div class="flex items-center space-x-2 mr-8">
      <span class="text-bronze text-xl font-semibold tracking-wide">🐺 Decebalus</span>
    </div>

    <!-- Links -->
    <ul class="flex space-x-6 flex-1">
      {#each links as { path, label }}
        <li>
          <Link
            to={path}
            class="nav-link text-sm font-medium transition-colors duration-200"
            getProps={({ isCurrent }) => ({ class: isCurrent ? 'active' : '' })}
          >
            {label}
          </Link>
        </li>
      {/each}
    </ul>

    <div class="flex items-center space-x-2 ml-auto">
      <div class={`w-3 h-3 rounded-full ${getStatusColor($connectionStatus)} shadow-glow`}></div>
      <span class="text-sm font-medium">{getStatusText($connectionStatus)}</span>
    </div>
  </div>
</nav>

<style lang="postcss">
  /* Navbar Styling */
  nav {
    backdrop-filter: blur(6px);
    border-bottom: 1px solid rgba(255, 140, 0, 0.3);
    padding: 0.75rem 1.5rem;
  }

  .nav-link {
    position: relative;
    text-decoration: none;
    color: white; /* Set link color to white */
    transition: color 0.3s ease, transform 0.3s ease; /* Add transform for a subtle effect */
  }

  .nav-link::after {
    content: "";
    position: absolute;
    bottom: -3px;
    left: 0;
    height: 2px;
    width: 0;
    background-color: #cd7f32; /* bronze accent */
    transition: width 0.3s ease-out; /* Smooth out the underline animation */
  }

  .nav-link:hover, .nav-link.active {
    color: #cd7f32; /* Change text color to bronze on hover or active */
    transform: translateY(-2px); /* Slightly lift the link on hover */
  }

  .nav-link:hover::after, .nav-link.active::after {
    width: 100%; /* Show underline effect on hover or active state */
  }
</style>
