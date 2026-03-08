<script lang="ts">
  import { onMount } from 'svelte';
  import { Router, Route } from 'svelte-routing';
  import { connectWebSocket, closeWebSocket } from './lib/stores/websocketStore';
  import Navbar from './lib/components/Navbar.svelte';
  import Dashboard from './lib/pages/Dashboard.svelte';
  import Reconnaissance from './lib/pages/Reconnaissance.svelte';
  import Attacks from './lib/pages/Attacks.svelte';
  import Plugins from './lib/pages/Plugins.svelte';
  import Logs from './lib/pages/Logs.svelte';
  import Settings from './lib/pages/Settings.svelte';

  onMount(() => {
    connectWebSocket();
    return closeWebSocket;
  });
</script>

<Router url="">
  <Navbar />
  <main>
    <Route path="/"><Dashboard /></Route>
    <Route path="/recon"><Reconnaissance /></Route>
    <Route path="/attacks"><Attacks /></Route>
    <Route path="/plugins"><Plugins /></Route>
    <Route path="/logs"><Logs /></Route>
    <Route path="/settings"><Settings /></Route>
    <Route path="*"><p>404 — Page not found.</p></Route>
  </main>
  <footer>
    <small>Decebalus v0.1.0-alpha</small>
  </footer>
</Router>
