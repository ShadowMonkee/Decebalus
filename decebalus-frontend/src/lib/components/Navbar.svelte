<script lang="ts">
  import { Link } from 'svelte-routing';
  import { connectionStatus } from '../stores/websocketStore';

  const links = [
    { path: '/',        label: 'Dashboard' },
    { path: '/recon',   label: 'Recon' },
    { path: '/logs',    label: 'Logs' },
    { path: '/attacks', label: 'Attacks' },
    { path: '/plugins', label: 'Plugins' },
    { path: '/settings', label: 'Settings' },
  ];

  const statusLabel: Record<string, string> = {
    connected:    'Connected',
    connecting:   'Connecting...',
    disconnected: 'Offline',
  };
</script>

<nav>
  <ul>
    <li><strong>🐺 Decebalus</strong></li>
  </ul>
  <ul>
    {#each links as { path, label }}
      <li>
        <Link
          to={path}
          getProps={({ isCurrent }) => ({ class: isCurrent ? 'active' : '' })}
        >{label}</Link>
      </li>
    {/each}
  </ul>
  <ul>
    <li>
      <span class="dot {$connectionStatus}" aria-hidden="true"></span>
      <small>{statusLabel[$connectionStatus]}</small>
    </li>
  </ul>
</nav>

<style>
  nav {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 100;
    backdrop-filter: blur(6px);
    border-bottom: 1px solid rgba(205, 127, 50, 0.3);
  }

  .dot {
    display: inline-block;
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 50%;
    margin-right: 0.3rem;
    vertical-align: middle;
  }
  .dot.connected    { background: #22c55e; }
  .dot.connecting   { background: #eab308; animation: blink 1s ease-in-out infinite; }
  .dot.disconnected { background: #ef4444; }

  @keyframes blink {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.3; }
  }

  :global(a.active) {
    color: var(--color-bronze);
    border-bottom: 2px solid var(--color-bronze);
    padding-bottom: 2px;
  }
</style>
