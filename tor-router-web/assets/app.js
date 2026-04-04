const REFRESH_INTERVAL = 10000;

const IFACE_ROLES = {
  eth0: 'WAN 1',
  wlan0: 'WAN 2',
  eth1: 'LAN Standard',
  eth2: 'LAN Tor 1',
  eth3: 'LAN Tor 2',
};

const MANAGED_SERVICES = [
  ['tor', 'Tor'],
  ['dnsmasq', 'dnsmasq'],
  ['nginx', 'nginx'],
  ['pihole', 'pihole-FTL'],
  ['dnscrypt', 'dnscrypt-proxy'],
  ['php_fpm', 'php-fpm'],
  ['wan_failover', 'wan-failover'],
  ['ssh', 'ssh'],
];

const I18N = {
  en: {
    ui: {
      langEnTitle: 'English (US)',
      langPtTitle: 'Português (Brasil)',
      torExitIp: 'Tor Exit IP',
      torBootstrap: 'Tor Bootstrap',
      wanState: 'WAN State',
      uptime: 'Uptime',
      torRotation: 'Tor IP Rotation Interval',
      current: 'Current:',
      setInterval: 'Set interval (seconds):',
      applyInterval: 'Apply Interval',
      rotationHint: 'Lower values rotate more often. Higher values keep circuits longer.',
      cpuUsage: 'CPU Usage',
      memoryUsage: 'Memory Usage',
      diskUsage: 'Disk Usage (/)',
      geoMap: 'Tor Exit GeoIP Map',
      locationUnavailable: 'Location unavailable.',
      servicesMonitor: 'Services Monitor',
      service: 'Service',
      active: 'Active',
      enabled: 'Enabled',
      actions: 'Actions',
      routerControls: 'Router Controls',
      start: 'Start',
      restart: 'Restart',
      stop: 'Stop',
      newCircuit: '🔄 New Circuit',
      restartTor: '↺ Restart Tor',
      reloadFirewall: 'Reload Firewall',
      troubleshoot: 'Troubleshoot (Tor LAN)',
      runDiagnostics: 'Run Diagnostics',
      fixDnsChain: 'Fix DNS/Tor Chain',
      reapplyFirewall: 'Reapply Firewall',
      restartRouterStack: 'Restart Router Stack',
      fullRecovery: 'Full Recovery',
      trblDefault: 'Click "Run Diagnostics" when Tor LAN clients cannot browse.',
      interfacesTraffic: 'Interfaces & Traffic',
      interface: 'Interface',
      state: 'State',
      dhcpClients: 'DHCP Clients',
      hostname: 'Hostname',
      network: 'Network',
      dnsQueriesToday: 'DNS Queries Today',
      blockedToday: 'Blocked Today',
      blockRate: 'Block Rate',
      wanManagement: 'WAN Management',
      primaryWan: 'Primary WAN:',
      wan1: 'eth0 (WAN 1)',
      wan2: 'wlan0 (WAN 2)',
      apply: 'Apply',
      vpnControl: 'VPN Control',
      profile: 'Profile:',
      selectOption: '— select —',
      connect: 'Connect',
      disconnect: 'Disconnect',
      uploadProfile: 'Upload profile (.conf/.ovpn):',
      upload: 'Upload',
      logs: 'Logs',
      loadLogs: 'Load Logs',
      logsDefault: 'Select a service and click "Load Logs".',
      configEditor: 'Configuration Editor',
      configFile: 'Config file:',
      load: 'Load',
      applyAfterSave: 'Apply after save:',
      saveConfig: 'Save Config'
    },
    geoUnavailable: 'Location unavailable.',
    unknown: 'Unknown',
    noLeases: 'No active DHCP leases.',
    wan: { normal: 'Normal', failover: 'Failover', nowan: 'NO WAN', manual: 'Manual' },
    wanHint: {
      normal: 'eth0 primary, wlan0 standby',
      failover: 'using wlan0',
      nowan: 'both WAN links are down',
      manual: 'manual route override',
    },
    feedback: {
      intervalRange: '✗ Interval must be between 10 and 86400 seconds.',
      applying: '⏳ Applying {s}s...',
      profileFirst: '✗ Select a profile first.',
      uploadFirst: '✗ Select a file first.',
      diagRunning: '⏳ Running diagnostics...',
      diagDone: '✓ Diagnostics completed.',
    }
  },
  pt: {
    ui: {
      langEnTitle: 'Inglês (EUA)',
      langPtTitle: 'Português (Brasil)',
      torExitIp: 'IP de Saída Tor',
      torBootstrap: 'Bootstrap do Tor',
      wanState: 'Estado da WAN',
      uptime: 'Tempo Ligado',
      torRotation: 'Intervalo de Rotação de IP Tor',
      current: 'Atual:',
      setInterval: 'Definir intervalo (segundos):',
      applyInterval: 'Aplicar Intervalo',
      rotationHint: 'Valores menores rotacionam com mais frequência. Valores maiores mantêm circuitos por mais tempo.',
      cpuUsage: 'Uso de CPU',
      memoryUsage: 'Uso de Memória',
      diskUsage: 'Uso de Disco (/)',
      geoMap: 'Mapa GeoIP da Saída Tor',
      locationUnavailable: 'Localização indisponível.',
      servicesMonitor: 'Monitor de Serviços',
      service: 'Serviço',
      active: 'Ativo',
      enabled: 'Habilitado',
      actions: 'Ações',
      routerControls: 'Controles do Roteador',
      start: 'Iniciar',
      restart: 'Reiniciar',
      stop: 'Parar',
      newCircuit: '🔄 Novo Circuito',
      restartTor: '↺ Reiniciar Tor',
      reloadFirewall: 'Recarregar Firewall',
      troubleshoot: 'Solução de Problemas (LAN Tor)',
      runDiagnostics: 'Executar Diagnóstico',
      fixDnsChain: 'Corrigir Cadeia DNS/Tor',
      reapplyFirewall: 'Reaplicar Firewall',
      restartRouterStack: 'Reiniciar Stack do Roteador',
      fullRecovery: 'Recuperação Completa',
      trblDefault: 'Clique em "Executar Diagnóstico" quando clientes da LAN Tor não conseguirem navegar.',
      interfacesTraffic: 'Interfaces e Tráfego',
      interface: 'Interface',
      state: 'Estado',
      dhcpClients: 'Clientes DHCP',
      hostname: 'Hostname',
      network: 'Rede',
      dnsQueriesToday: 'Consultas DNS Hoje',
      blockedToday: 'Bloqueados Hoje',
      blockRate: 'Taxa de Bloqueio',
      wanManagement: 'Gerenciamento WAN',
      primaryWan: 'WAN Primária:',
      wan1: 'eth0 (WAN 1)',
      wan2: 'wlan0 (WAN 2)',
      apply: 'Aplicar',
      vpnControl: 'Controle de VPN',
      profile: 'Perfil:',
      selectOption: '— selecionar —',
      connect: 'Conectar',
      disconnect: 'Desconectar',
      uploadProfile: 'Enviar perfil (.conf/.ovpn):',
      upload: 'Enviar',
      logs: 'Logs',
      loadLogs: 'Carregar Logs',
      logsDefault: 'Selecione um serviço e clique em "Carregar Logs".',
      configEditor: 'Editor de Configuração',
      configFile: 'Arquivo de configuração:',
      load: 'Carregar',
      applyAfterSave: 'Aplicar após salvar:',
      saveConfig: 'Salvar Configuração'
    },
    geoUnavailable: 'Localização indisponível.',
    unknown: 'Desconhecido',
    noLeases: 'Sem leases DHCP ativos.',
    wan: { normal: 'Normal', failover: 'Failover', nowan: 'SEM WAN', manual: 'Manual' },
    wanHint: {
      normal: 'eth0 primária, wlan0 standby',
      failover: 'usando wlan0',
      nowan: 'ambos links WAN estão indisponíveis',
      manual: 'override manual de rota',
    },
    feedback: {
      intervalRange: '✗ O intervalo deve ficar entre 10 e 86400 segundos.',
      applying: '⏳ Aplicando {s}s...',
      profileFirst: '✗ Selecione um perfil primeiro.',
      uploadFirst: '✗ Selecione um arquivo primeiro.',
      diagRunning: '⏳ Executando diagnóstico...',
      diagDone: '✓ Diagnóstico concluído.',
    }
  }
};

let LANG = localStorage.getItem('tsr-lang') || 'en';
if (!['en', 'pt'].includes(LANG)) LANG = 'en';

const t = (path, vars = {}) => {
  const val = path.split('.').reduce((o, k) => (o && o[k] !== undefined ? o[k] : null), I18N[LANG]) ?? path;
  if (typeof val !== 'string') return val;
  return Object.entries(vars).reduce((s, [k, v]) => s.replace(`{${k}}`, String(v)), val);
};

function applyLangButtons() {
  const en = document.getElementById('lang-en');
  const pt = document.getElementById('lang-pt');
  if (en) en.classList.toggle('active', LANG === 'en');
  if (pt) pt.classList.toggle('active', LANG === 'pt');
}

function applyI18nUI() {
  document.documentElement.setAttribute('lang', LANG === 'pt' ? 'pt-BR' : 'en');
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const key = el.getAttribute('data-i18n');
    if (!key) return;
    el.textContent = t(key);
  });
  document.querySelectorAll('[data-i18n-title]').forEach((el) => {
    const key = el.getAttribute('data-i18n-title');
    if (!key) return;
    el.setAttribute('title', t(key));
  });
}

function updateClock() {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}
setInterval(updateClock, 1000);
updateClock();
applyLangButtons();
applyI18nUI();

function setBar(id, pct) {
  const el = document.getElementById(id);
  if (!el) return;
  const clamped = Math.max(0, Math.min(100, Number(pct || 0)));
  el.style.width = `${clamped}%`;
  el.classList.toggle('warn', clamped >= 70 && clamped < 90);
  el.classList.toggle('crit', clamped >= 90);
}

function feedback(id, msg, isError = false) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.className = `feedback${isError ? ' error' : ''}`;
  setTimeout(() => { if (el.textContent === msg) el.textContent = ''; }, 6000);
}

async function api(path, body = null) {
  const opts = body
    ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
    : { method: 'GET' };
  const res = await fetch(path, opts);
  return res.json();
}

async function controlAction(action, extra = {}) {
  return api('/api/control.php', { action, ...extra });
}

function renderServices(details = {}) {
  const tbody = document.getElementById('services-tbody');
  tbody.innerHTML = '';
  for (const [key, label] of MANAGED_SERVICES) {
    const d = details[key] || {};
    const tr = document.createElement('tr');
    const active = d.active || 'inactive';
    const activeClass = active === 'active' ? 'pill ok' : 'pill bad';
    tr.innerHTML = `
      <td>${label}</td>
      <td><span class="${activeClass}">${active}</span></td>
      <td>${d.enabled || 'unknown'}</td>
      <td class="action-cell">
        <button class="btn btn-secondary tiny" data-op="start" data-svc="${key}">Start</button>
        <button class="btn btn-warn tiny" data-op="restart" data-svc="${key}">Restart</button>
        <button class="btn btn-danger tiny" data-op="stop" data-svc="${key}">Stop</button>
      </td>`;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll('button[data-op]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const service = btn.dataset.svc;
      const operation = btn.dataset.op;
      feedback('services-feedback', `⏳ ${operation} ${service}...`);
      const r = await controlAction('service_action', { service, operation });
      feedback('services-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
      if (r.ok) setTimeout(refreshStatus, 1000);
    });
  });
}

function renderInterfaces(network = {}, ifaceDetails = {}) {
  const tbody = document.getElementById('net-tbody');
  tbody.innerHTML = '';
  for (const iface of Object.keys(IFACE_ROLES)) {
    const s = network[iface] || {};
    const d = ifaceDetails[iface] || {};
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${iface}</code> <span class="hint">${IFACE_ROLES[iface]}</span></td>
      <td>${d.state || 'unknown'}</td>
      <td>${d.ipv4 || '—'}</td>
      <td>${(s.rx_mb ?? 0).toLocaleString()}</td>
      <td>${(s.tx_mb ?? 0).toLocaleString()}</td>`;
    tbody.appendChild(tr);
  }
}

function renderClients(clients = { leases: [] }) {
  const tbody = document.getElementById('clients-tbody');
  tbody.innerHTML = '';
  const leases = clients.leases || [];
  leases.forEach((c) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${c.ip}</td>
      <td>${c.hostname || '—'}</td>
      <td><code>${c.mac}</code></td>
      <td>${c.network}</td>`;
    tbody.appendChild(tr);
  });
  if (!leases.length) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="4">${t('noLeases')}</td>`;
    tbody.appendChild(tr);
  }
}

function updateGeoMap(geo = {}) {
  const meta = document.getElementById('geoip-meta');
  const frame = document.getElementById('geoip-map-frame');
  if (!meta || !frame) return;

  if (!geo.available || geo.latitude == null || geo.longitude == null) {
    meta.textContent = t('geoUnavailable');
    frame.removeAttribute('src');
    return;
  }

  const city = [geo.city, geo.region, geo.country].filter(Boolean).join(', ');
  const org = geo.org ? ` • ${geo.org}` : '';
  meta.textContent = `${geo.ip} • ${city || t('unknown')}${org}`;

  const lat = Number(geo.latitude).toFixed(6);
  const lon = Number(geo.longitude).toFixed(6);
  const mapSrc = `https://www.openstreetmap.org/export/embed.html?bbox=${lon}%2C${lat}%2C${lon}%2C${lat}&layer=mapnik&marker=${lat}%2C${lon}`;
  if (frame.getAttribute('src') !== mapSrc) {
    frame.setAttribute('src', mapSrc);
  }
}

async function refreshStatus() {
  let data;
  try {
    data = await api('/api/status.php');
  } catch (err) {
    console.error(err);
    return;
  }

  document.getElementById('tor-exit-ip').textContent = data.tor_exit_ip || '—';
  document.getElementById('sys-uptime').textContent = data.system?.uptime_human || '—';
  document.getElementById('sys-hostname').textContent = `${data.system?.hostname || ''} • kernel ${data.system?.kernel || ''}`;

  const tb = data.tor_bootstrap || {};
  document.getElementById('tor-bootstrap').textContent = `${tb.percent ?? 0}%`;
  document.getElementById('tor-bootstrap-phase').textContent = tb.phase || '';

  const torRotation = Number(data.tor_rotation_interval_sec || 600);
  const curEl = document.getElementById('tor-rotation-current');
  if (curEl) curEl.value = `${torRotation}s`;
  const setEl = document.getElementById('tor-rotation-seconds');
  if (setEl && document.activeElement !== setEl) setEl.value = torRotation;

  const ws = data.wan_state || 'unknown';
  const wanEl = document.getElementById('wan-state');
  const wanHint = document.getElementById('wan-hint');
  wanEl.textContent = (I18N[LANG].wan[ws] || ws);
  wanEl.style.color = ws === 'nowan' ? 'var(--red)' : (ws === 'failover' ? 'var(--yellow)' : 'var(--green)');
  wanHint.textContent = I18N[LANG].wanHint[ws] || '';

  const cpu = Number(data.cpu_percent || 0);
  document.getElementById('cpu-val').textContent = cpu.toFixed(1);
  setBar('cpu-bar', cpu);

  const mem = data.memory || {};
  document.getElementById('mem-val').textContent = Number(mem.percent || 0).toFixed(1);
  document.getElementById('mem-used').textContent = mem.used_mb ?? 0;
  document.getElementById('mem-total').textContent = mem.total_mb ?? 0;
  setBar('mem-bar', mem.percent || 0);

  const disk = data.system?.disk_root || {};
  document.getElementById('disk-val').textContent = Number(disk.percent || 0).toFixed(1);
  document.getElementById('disk-used').textContent = disk.used_gb ?? 0;
  document.getElementById('disk-total').textContent = disk.total_gb ?? 0;
  setBar('disk-bar', disk.percent || 0);

  const ph = data.pihole || {};
  if (ph.available) {
    document.getElementById('ph-total').textContent = (ph.dns_queries_today || 0).toLocaleString();
    document.getElementById('ph-blocked').textContent = (ph.ads_blocked_today || 0).toLocaleString();
    document.getElementById('ph-pct').textContent = `${Number(ph.ads_percentage || 0).toFixed(1)}%`;
  } else {
    document.getElementById('ph-total').textContent = 'N/A';
    document.getElementById('ph-blocked').textContent = 'N/A';
    document.getElementById('ph-pct').textContent = 'N/A';
  }

  const profileSel = document.getElementById('vpn-profile-select');
  const current = profileSel.value;
  profileSel.innerHTML = '<option value="">— select —</option>';
  profileSel.innerHTML = `<option value="">${t('ui.selectOption')}</option>`;
  (data.vpn_profiles || []).forEach((p) => {
    const opt = document.createElement('option');
    opt.value = p;
    opt.textContent = p;
    if (p === current) opt.selected = true;
    profileSel.appendChild(opt);
  });

  renderServices(data.service_details || {});
  renderInterfaces(data.network || {}, data.interfaces || {});
  renderClients(data.clients || { leases: [] });
  updateGeoMap(data.tor_exit_geoip || {});
}

document.getElementById('btn-new-circuit').addEventListener('click', async () => {
  feedback('router-feedback', '⏳ Requesting new circuit...');
  const r = await controlAction('tor_new_circuit');
  feedback('router-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-restart-tor').addEventListener('click', async () => {
  feedback('router-feedback', '⏳ Restarting Tor...');
  const r = await controlAction('tor_restart');
  feedback('router-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-tor-rotation-save').addEventListener('click', async () => {
  const input = document.getElementById('tor-rotation-seconds');
  const seconds = Number(input?.value || 0);
  if (!Number.isFinite(seconds) || seconds < 10 || seconds > 86400) {
    feedback('tor-rotation-feedback', t('feedback.intervalRange'), true);
    return;
  }
  feedback('tor-rotation-feedback', t('feedback.applying', { s: seconds }));
  const r = await controlAction('tor_set_rotation_interval', { seconds });
  feedback('tor-rotation-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
  if (r.ok) setTimeout(refreshStatus, 2500);
});

function applyRotationPreset(seconds) {
  const input = document.getElementById('tor-rotation-seconds');
  if (input) input.value = String(seconds);
  document.getElementById('btn-tor-rotation-save').click();
}

document.getElementById('btn-rot-300').addEventListener('click', () => applyRotationPreset(300));
document.getElementById('btn-rot-600').addEventListener('click', () => applyRotationPreset(600));
document.getElementById('btn-rot-1800').addEventListener('click', () => applyRotationPreset(1800));
document.getElementById('btn-rot-3600').addEventListener('click', () => applyRotationPreset(3600));

document.getElementById('btn-firewall-reload').addEventListener('click', async () => {
  feedback('router-feedback', '⏳ Reloading firewall...');
  const r = await controlAction('firewall_reload');
  feedback('router-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-router-start').addEventListener('click', async () => {
  feedback('router-feedback', '⏳ Starting router...');
  const r = await controlAction('router_start');
  feedback('router-feedback', r.ok ? '✓ Router started' : `✗ ${r.message}`, !r.ok);
  if (r.ok) setTimeout(refreshStatus, 2000);
});

document.getElementById('btn-router-stop').addEventListener('click', async () => {
  feedback('router-feedback', '⏳ Stopping router...');
  const r = await controlAction('router_stop');
  feedback('router-feedback', r.ok ? '✓ Router stopped' : `✗ ${r.message}`, !r.ok);
  if (r.ok) setTimeout(refreshStatus, 2000);
});

document.getElementById('btn-router-restart').addEventListener('click', async () => {
  feedback('router-feedback', '⏳ Restarting router...');
  const r = await controlAction('router_restart');
  feedback('router-feedback', r.ok ? '✓ Router restarted' : `✗ ${r.message}`, !r.ok);
  if (r.ok) setTimeout(refreshStatus, 2500);
});

document.getElementById('btn-set-wan').addEventListener('click', async () => {
  const iface = document.getElementById('wan-select').value;
  feedback('wan-feedback', `⏳ Setting primary WAN to ${iface}...`);
  const r = await controlAction('wan_set_primary', { interface: iface });
  feedback('wan-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-vpn-connect').addEventListener('click', async () => {
  const profile = document.getElementById('vpn-profile-select').value;
  if (!profile) return feedback('vpn-feedback', t('feedback.profileFirst'), true);
  feedback('vpn-feedback', `⏳ Connecting ${profile}...`);
  const r = await controlAction('vpn_connect', { profile });
  feedback('vpn-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-vpn-disconnect').addEventListener('click', async () => {
  feedback('vpn-feedback', '⏳ Disconnecting VPN...');
  const r = await controlAction('vpn_disconnect');
  feedback('vpn-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-vpn-upload').addEventListener('click', async () => {
  const fileInput = document.getElementById('vpn-file-input');
  if (!fileInput.files.length) return feedback('vpn-feedback', t('feedback.uploadFirst'), true);
  const formData = new FormData();
  formData.append('action', 'vpn_upload');
  formData.append('file', fileInput.files[0]);
  feedback('vpn-feedback', '⏳ Uploading profile...');
  const res = await fetch('/api/control.php', { method: 'POST', body: formData });
  const r = await res.json();
  feedback('vpn-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
  if (r.ok) fileInput.value = '';
});

document.getElementById('btn-load-logs').addEventListener('click', async () => {
  const service = document.getElementById('logs-service').value;
  feedback('logs-feedback', `⏳ Loading ${service} logs...`);
  const r = await controlAction('logs_get', { service, lines: 80 });
  if (r.ok) {
    document.getElementById('logs-output').textContent = r.logs || '(empty)';
    feedback('logs-feedback', '✓ Logs loaded');
  } else {
    feedback('logs-feedback', `✗ ${r.message}`, true);
  }
});

document.getElementById('btn-config-load').addEventListener('click', async () => {
  const config_key = document.getElementById('config-key').value;
  feedback('config-feedback', `⏳ Loading ${config_key}...`);
  const r = await controlAction('config_get', { config_key });
  if (r.ok) {
    document.getElementById('config-content').value = r.content || '';
    feedback('config-feedback', `✓ Loaded ${r.path}`);
  } else {
    feedback('config-feedback', `✗ ${r.message}`, true);
  }
});

document.getElementById('btn-config-save').addEventListener('click', async () => {
  const config_key = document.getElementById('config-key').value;
  const content = document.getElementById('config-content').value;
  const apply_action = document.getElementById('config-apply').value;
  feedback('config-feedback', `⏳ Saving ${config_key}...`);
  const r = await controlAction('config_set', { config_key, content, apply_action });
  feedback('config-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-trbl-check').addEventListener('click', async () => {
  feedback('trbl-feedback', t('feedback.diagRunning'));
  const r = await controlAction('troubleshoot_run');
  if (r.ok) {
    document.getElementById('trbl-output').textContent = r.output || '(empty)';
    feedback('trbl-feedback', t('feedback.diagDone'));
  } else {
    feedback('trbl-feedback', `✗ ${r.message}`, true);
  }
});

document.getElementById('lang-en').addEventListener('click', () => {
  LANG = 'en';
  localStorage.setItem('tsr-lang', 'en');
  applyLangButtons();
  applyI18nUI();
  refreshStatus();
});

document.getElementById('lang-pt').addEventListener('click', () => {
  LANG = 'pt';
  localStorage.setItem('tsr-lang', 'pt');
  applyLangButtons();
  applyI18nUI();
  refreshStatus();
});

async function runTroubleshootFix(mode, label) {
  feedback('trbl-feedback', `⏳ ${label}...`);
  const r = await controlAction('troubleshoot_fix', { mode });
  document.getElementById('trbl-output').textContent = r.output || r.message || '(no output)';
  feedback('trbl-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
  if (r.ok) setTimeout(refreshStatus, 2500);
}

document.getElementById('btn-trbl-fix-dns').addEventListener('click', () => runTroubleshootFix('dns', 'Fixing DNS/Tor chain'));
document.getElementById('btn-trbl-fix-firewall').addEventListener('click', () => runTroubleshootFix('firewall', 'Reapplying firewall'));
document.getElementById('btn-trbl-fix-stack').addEventListener('click', () => runTroubleshootFix('stack', 'Restarting router stack'));
document.getElementById('btn-trbl-fix-full').addEventListener('click', () => runTroubleshootFix('full', 'Running full recovery'));

refreshStatus();
setInterval(refreshStatus, REFRESH_INTERVAL);
