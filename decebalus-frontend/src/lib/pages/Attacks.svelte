<script>
  // Placeholder for attacks page
  let attacks = [
    { id: 1, name: 'WiFi Deauthentication', category: 'WiFi', icon: '📡', status: 'ready' },
    { id: 2, name: 'Evil Twin AP', category: 'WiFi', icon: '👥', status: 'ready' },
    { id: 3, name: 'DNS Spoofing', category: 'Network', icon: '🌐', status: 'ready' },
    { id: 4, name: 'ARP Poisoning', category: 'Network', icon: '🎯', status: 'ready' },
  ];
</script>

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