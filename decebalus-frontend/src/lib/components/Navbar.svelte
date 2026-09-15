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
        <span class="brand-mark" aria-hidden="true">D</span>
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
    height: var(--nav-height);
    padding: 0 1.5rem;
    background: var(--nav-bg);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--line);
  }

  /* Brand */
  .brand {
    display: flex;
    align-items: center;
    gap: 0.7rem;
    color: var(--text);
    white-space: nowrap;
  }

  .brand-mark {
    width: 26px;
    height: 26px;
    flex-shrink: 0;
    display: grid;
    place-items: center;
    border: 1px solid var(--strong);
    border-radius: var(--radius-sm);
    color: var(--accent);
    font-family: var(--font-mono);
    font-size: 0.8rem;
    line-height: 1;
    transition: border-color 0.2s ease;
  }
  .brand:hover .brand-mark { border-color: var(--accent); }

  .brand-name {
    font-weight: 500;
    font-size: 0.78rem;
    letter-spacing: 0.18em;
  }

  /* Nav links */
  .nav-links {
    flex: 1;
    justify-content: center;
    gap: 0.15rem;
  }

  :global(.nav-links a) {
    padding: 0.35rem 0.7rem;
    border-radius: var(--radius-sm);
    font-size: 0.8rem;
    color: var(--text-2);
    transition: color 0.15s ease, background-color 0.15s ease;
  }
  :global(.nav-links a:hover) {
    color: var(--text);
    background: var(--raised);
  }

  /* Active link */
  :global(.nav-links a.active) {
    color: var(--accent);
    background: var(--accent-glow);
  }

  /* Connection status */
  .status-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .status-label {
    white-space: nowrap;
    color: var(--text-2);
    font-family: var(--font-mono);
    font-size: 0.66rem;
    letter-spacing: 0.14em;
    text-transform: uppercase;
  }

  .dot {
    display: inline-block;
    width: 0.4rem;
    height: 0.4rem;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .dot.connected    { background: var(--sage); animation: live-pulse 2.4s ease-in-out infinite; }
  .dot.connecting   { background: var(--amber); animation: blink 1s ease-in-out infinite; }
  .dot.disconnected { background: var(--clay); }
</style>
