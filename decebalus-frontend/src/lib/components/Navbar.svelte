<script lang="ts">
  import { Link } from 'svelte-routing';
  import { connectionStatus } from '../stores/websocketStore';

  const links = [
    { path: '/',            label: 'Dashboard'  },
    { path: '/war',         label: 'War Table'  },
    { path: '/engagements', label: 'Engagement' },
    { path: '/recon',       label: 'Recon'      },
    { path: '/logs',        label: 'Logs'       },
    { path: '/attacks',     label: 'Attacks'    },
    { path: '/plugins',     label: 'Modules'    },
    { path: '/vulndb',      label: 'Vuln DB'    },
    { path: '/history',     label: 'History'    },
    { path: '/settings',    label: 'Settings'   },
  ];

  const statusLabel: Record<string, string> = {
    connected:    'Connected',
    connecting:   'Connecting…',
    disconnected: 'Offline',
  };
</script>

<nav>
  <ul>
    <li>
      <strong class="brand">
        <!-- Targeting/crosshair mark — represents network scanning -->
        <svg class="brand-icon" width="18" height="18" viewBox="0 0 18 18" fill="none"
             xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <circle cx="9" cy="9" r="6.5" stroke="currentColor" stroke-width="1.4"/>
          <circle cx="9" cy="9" r="2.5" fill="currentColor"/>
          <line x1="9" y1="1.5" x2="9" y2="4.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
          <line x1="9" y1="13.5" x2="9" y2="16.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
          <line x1="1.5" y1="9" x2="4.5" y2="9" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
          <line x1="13.5" y1="9" x2="16.5" y2="9" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
        </svg>
        <span class="brand-name">DECEBALUS</span>
      </strong>
    </li>
  </ul>

  <ul class="nav-links">
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
    <li class="status-item">
      <span class="dot {$connectionStatus}" aria-hidden="true"></span>
      <small class="status-label">{statusLabel[$connectionStatus]}</small>
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
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--border-bronze-subtle);
  }

  /* Brand */
  .brand {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    color: var(--color-bronze);
    letter-spacing: 0.08em;
    font-size: 0.88rem;
    white-space: nowrap;
  }

  .brand-icon {
    color: var(--color-bronze);
    flex-shrink: 0;
    transition: filter 0.2s ease;
  }

  .brand:hover .brand-icon {
    filter: drop-shadow(0 0 4px var(--color-bronze-glow));
  }

  .brand-name {
    font-weight: 700;
  }

  /* Nav links */
  .nav-links {
    flex: 1;
    justify-content: center;
  }

  /* Active link */
  :global(a.active) {
    color: var(--color-bronze-bright);
    border-bottom: 2px solid var(--color-bronze);
    padding-bottom: 2px;
  }

  /* Connection status */
  .status-item {
    display: flex;
    align-items: center;
    gap: 0.35rem;
  }

  .status-label {
    white-space: nowrap;
    color: var(--color-ash);
  }

  .dot {
    display: inline-block;
    width: 0.5rem;
    height: 0.5rem;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .dot.connected    { background: #22c55e; box-shadow: 0 0 4px rgba(34,197,94,0.5); }
  .dot.connecting   { background: #eab308; animation: blink 1s ease-in-out infinite; }
  .dot.disconnected { background: #ef4444; }

  @keyframes blink {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.25; }
  }
</style>
