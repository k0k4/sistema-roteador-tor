const REFRESH_INTERVAL = 10000;

const IFACE_ROLES = {
  eth0: 'WAN 1',
  wlan0: 'WAN 2',
  eth1: 'LAN Standard',
  eth2: 'LAN Tor 1',
  eth3: 'LAN Tor 2',
};

const SECTIONS = ['overview', 'tor', 'network', 'services', 'wifi', 'vpn', 'bypass', 'logs', 'config', 'pentest'];

const MANAGED_SERVICES = [
  ['tor', 'Tor'],
  ['dnsmasq', 'dnsmasq'],
  ['nginx', 'nginx'],
  ['pihole', 'Pi-hole'],
  ['dnscrypt', 'dnscrypt-proxy'],
  ['php_fpm', 'PHP-FPM'],
  ['wan_failover', 'WAN Failover'],
  ['ssh', 'SSH'],
  ['hostapd', 'Wi-Fi AP'],
  ['pentest', 'Wi-Fi Security Audit Suite'],
];

const I18N = {
  en: {
    nav: {
      overview: 'Overview',
      tor: 'Tor',
      network: 'Network',
      services: 'Services',
      wifi: 'Wi-Fi AP',
      vpn: 'VPN',
      bypass: 'Bypass',
      logs: 'Logs',
      config: 'Config',
      pentest: 'Wi-Fi Security Audit Suite',
    },
    overview: {
      desc: 'Real-time status of your Tor Security Router.',
      quickStats: 'Quick Stats',
      dhcpClients: 'DHCP Clients',
      vpnStatus: 'VPN',
    },
    tor: {
      desc: 'Tor circuit status, geo-location and rotation settings.',
      actions: 'Tor Actions',
    },
    network: { desc: 'Interfaces, DHCP leases and WAN management.' },
    services: { desc: 'Monitor and control managed services.' },
    wifi: { desc: 'Create a Wi-Fi network routed through normal or Tor profiles.' },
    vpn: { desc: 'Connect, disconnect and upload VPN profiles.' },
    bypass: { desc: 'Destinations on Tor LANs that should route directly through WAN.' },
    logs: { desc: 'Inspect logs from managed services.' },
    config: { desc: 'Edit configuration files and apply changes.' },
    pentest: {
      desc: 'Wi-Fi security audit: scanner, traffic auditor and device fingerprinting.',
      refreshFrame: 'Reload Tool',
      hint: 'The audit suite runs in an isolated frame below.',
    },
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
      routerControls: 'Quick Controls',
      start: 'Start',
      restart: 'Restart',
      stop: 'Stop',
      newCircuit: 'New Circuit',
      restartTor: 'Restart Tor',
      reloadFirewall: 'Reload Firewall',
      troubleshoot: 'Troubleshoot',
      runDiagnostics: 'Run Diagnostics',
      fixDnsChain: 'Fix DNS/Tor',
      reapplyFirewall: 'Reapply FW',
      restartRouterStack: 'Restart Stack',
      fullRecovery: 'Full Recovery',
      trblDefault: 'Click "Run Diagnostics" when Tor LAN clients cannot browse.',
      interfacesTraffic: 'Interfaces & Traffic',
      interface: 'Interface',
      state: 'State',
      dhcpClients: 'DHCP Clients',
      hostname: 'Hostname',
      network: 'Network',
      dnsQueriesToday: 'DNS Queries',
      blockedToday: 'Blocked',
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
      saveConfig: 'Save Config',
      wifiApRouter: 'Wi-Fi SSID Router',
      wifiInterface: 'Wi-Fi interface:',
      autoSelect: 'Auto-select available',
      routeProfile: 'Route profile:',
      route10: '192.168.10.x (normal)',
      route20: '192.168.20.x (Tor)',
      route30: '192.168.30.x (Tor)',
      ssidName: 'SSID name:',
      wifiPassword: 'Wi-Fi password:',
      startWifiAp: 'Start SSID',
      stopWifiAp: 'Stop SSID',
      wifiApStatusIdle: 'SSID service is stopped.',
      wifiApRunning: 'Running on {iface} • SSID "{ssid}" • profile {route} • {subnet}',
      bypassList: 'Bypass List',
      bypassDesc: 'Sites, IPs or CIDRs on Tor LANs that should route directly through WAN instead of Tor.',
      bypassEntry: 'Domain / IP / CIDR',
      add: 'Add',
      reapplyList: 'Reapply / Resolve',
      bypassActiveIps: 'Active Bypass IPs',
      bypassActiveDesc: 'Resolved IPv4 addresses currently allowed to bypass Tor on eth2/eth3.',
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
      wifiSsidRequired: '✗ Enter SSID (1..32 chars).',
      wifiPasswordRequired: '✗ Enter Wi-Fi password (8..63 chars).',
      wifiStarting: '⏳ Starting Wi-Fi SSID...',
      wifiStopping: '⏳ Stopping Wi-Fi SSID...',
      wifiNoIface: '✗ No Wi-Fi interface available for AP (in use as WAN).',
      bypassEntryRequired: '✗ Enter a domain, IP or CIDR.',
      bypassEntryInvalid: '✗ Invalid entry. Use a domain, IPv4 or CIDR.',
      bypassAdding: '⏳ Adding...',
      bypassRemoving: '⏳ Removing...',
      bypassApplying: '⏳ Resolving and applying...',
    }
  },
  pt: {
    nav: {
      overview: 'Visão Geral',
      tor: 'Tor',
      network: 'Rede',
      services: 'Serviços',
      wifi: 'Wi-Fi AP',
      vpn: 'VPN',
      bypass: 'Bypass',
      logs: 'Logs',
      config: 'Config',
      pentest: 'Suíte de Auditoria Wi-Fi',
    },
    overview: {
      desc: 'Status em tempo real do seu Tor Security Router.',
      quickStats: 'Estatísticas Rápidas',
      dhcpClients: 'Clientes DHCP',
      vpnStatus: 'VPN',
    },
    tor: {
      desc: 'Status do circuito Tor, geolocalização e configuração de rotação.',
      actions: 'Ações do Tor',
    },
    network: { desc: 'Interfaces, leases DHCP e gerenciamento WAN.' },
    services: { desc: 'Monitore e controle os serviços gerenciados.' },
    wifi: { desc: 'Crie uma rede Wi-Fi roteada pelos perfis normal ou Tor.' },
    vpn: { desc: 'Conecte, desconecte e envie perfis VPN.' },
    bypass: { desc: 'Destinos nas LANs Tor que devem sair pela WAN direta.' },
    logs: { desc: 'Inspecione logs dos serviços gerenciados.' },
    config: { desc: 'Edite arquivos de configuração e aplique alterações.' },
    pentest: {
      desc: 'Auditoria de segurança Wi-Fi: scanner, auditor de tráfego e fingerprint de dispositivos.',
      refreshFrame: 'Recarregar Ferramenta',
      hint: 'A suíte de auditoria roda em um frame isolado abaixo.',
    },
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
      routerControls: 'Controles Rápidos',
      start: 'Iniciar',
      restart: 'Reiniciar',
      stop: 'Parar',
      newCircuit: 'Novo Circuito',
      restartTor: 'Reiniciar Tor',
      reloadFirewall: 'Recarregar Firewall',
      troubleshoot: 'Solução de Problemas',
      runDiagnostics: 'Executar Diagnóstico',
      fixDnsChain: 'Corrigir DNS/Tor',
      reapplyFirewall: 'Reaplicar FW',
      restartRouterStack: 'Reiniciar Stack',
      fullRecovery: 'Recuperação Completa',
      trblDefault: 'Clique em "Executar Diagnóstico" quando clientes da LAN Tor não conseguirem navegar.',
      interfacesTraffic: 'Interfaces e Tráfego',
      interface: 'Interface',
      state: 'Estado',
      dhcpClients: 'Clientes DHCP',
      hostname: 'Hostname',
      network: 'Rede',
      dnsQueriesToday: 'Consultas DNS',
      blockedToday: 'Bloqueados',
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
      saveConfig: 'Salvar Configuração',
      wifiApRouter: 'Roteador SSID Wi-Fi',
      wifiInterface: 'Interface Wi-Fi:',
      autoSelect: 'Selecionar automaticamente disponível',
      routeProfile: 'Perfil de rota:',
      route10: '192.168.10.x (normal)',
      route20: '192.168.20.x (Tor)',
      route30: '192.168.30.x (Tor)',
      ssidName: 'Nome do SSID:',
      wifiPassword: 'Senha do Wi-Fi:',
      startWifiAp: 'Iniciar SSID',
      stopWifiAp: 'Parar SSID',
      wifiApStatusIdle: 'Serviço SSID está parado.',
      wifiApRunning: 'Rodando em {iface} • SSID "{ssid}" • perfil {route} • {subnet}',
      bypassList: 'Lista de Bypass',
      bypassDesc: 'Sites, IPs ou CIDRs nas LANs Tor que devem sair pela WAN direta em vez do Tor.',
      bypassEntry: 'Domínio / IP / CIDR',
      add: 'Adicionar',
      reapplyList: 'Reaplicar / Resolver',
      bypassActiveIps: 'IPs Ativos de Bypass',
      bypassActiveDesc: 'Endereços IPv4 resolvidos atualmente autorizados a bypassar o Tor nas eth2/eth3.',
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
      wifiSsidRequired: '✗ Informe o SSID (1..32 caracteres).',
      wifiPasswordRequired: '✗ Informe a senha Wi-Fi (8..63 caracteres).',
      wifiStarting: '⏳ Iniciando SSID Wi-Fi...',
      wifiStopping: '⏳ Parando SSID Wi-Fi...',
      wifiNoIface: '✗ Nenhuma interface Wi-Fi disponível para AP (em uso como WAN).',
      bypassEntryRequired: '✗ Informe um domínio, IP ou CIDR.',
      bypassEntryInvalid: '✗ Entrada inválida. Use domínio, IPv4 ou CIDR.',
      bypassAdding: '⏳ Adicionando...',
      bypassRemoving: '⏳ Removendo...',
      bypassApplying: '⏳ Resolvendo e aplicando...',
    }
  }
};

let LANG = localStorage.getItem('tsr-lang') || 'en';
if (!['en', 'pt'].includes(LANG)) LANG = 'en';
let _statusPending = false;

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
    const txt = t(key);
    if (txt !== undefined) el.textContent = txt;
  });
  document.querySelectorAll('[data-i18n-title]').forEach((el) => {
    const key = el.getAttribute('data-i18n-title');
    if (!key) return;
    const txt = t(key);
    if (txt !== undefined) el.setAttribute('title', txt);
  });
}

function updateClock() {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString();
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

async function api(path, body = null, timeoutMs = 10000) {
  const opts = body
    ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
    : { method: 'GET' };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(path, { ...opts, signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

async function controlAction(action, extra = {}) {
  return api('/api/control.php', { action, ...extra });
}

/* ── Navigation ────────────────────────────── */
function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item[data-section]');
  const sections = document.querySelectorAll('.section');
  const topbarTitle = document.querySelector('.topbar-title');
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  const toggle = document.getElementById('menu-toggle');

  function showSection(sectionId) {
    navItems.forEach((n) => n.classList.toggle('active', n.dataset.section === sectionId));
    sections.forEach((s) => s.classList.toggle('active', s.id === `section-${sectionId}`));
    if (topbarTitle) topbarTitle.textContent = t(`nav.${sectionId}`);
    document.body.classList.remove('sidebar-open');
    window.scrollTo(0, 0);
  }

  navItems.forEach((item) => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      showSection(item.dataset.section);
    });
  });

  if (toggle && sidebar && overlay) {
    toggle.addEventListener('click', () => document.body.classList.toggle('sidebar-open'));
    overlay.addEventListener('click', () => document.body.classList.remove('sidebar-open'));
  }

  const hash = window.location.hash.replace('#', '');
  if (SECTIONS.includes(hash)) showSection(hash);
}

/* ── Rendering helpers ─────────────────────── */
function renderServices(details = {}) {
  const tbody = document.getElementById('services-tbody');
  if (!tbody) return;
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
  if (!tbody) return;
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
  if (!tbody) return;
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

function renderWifiAp(wifi = {}) {
  const ifaceSel = document.getElementById('wifi-ap-iface');
  const statusEl = document.getElementById('wifi-ap-status');
  if (!ifaceSel || !statusEl) return;

  const previous = ifaceSel.value;
  ifaceSel.innerHTML = `<option value="">${t('ui.autoSelect')}</option>`;
  const interfaces = Array.isArray(wifi.interfaces) ? wifi.interfaces : [];
  let availableCount = 0;

  interfaces.forEach((i) => {
    const opt = document.createElement('option');
    opt.value = i.name;
    const suffix = i.available ? '' : ' (WAN)';
    opt.textContent = `${i.name}${suffix}`;
    opt.disabled = !i.available;
    if (i.available) availableCount += 1;
    ifaceSel.appendChild(opt);
  });

  if (previous && [...ifaceSel.options].some((o) => o.value === previous)) {
    ifaceSel.value = previous;
  }
  ifaceSel.disabled = availableCount === 0;

  if (wifi.running) {
    statusEl.textContent = t('ui.wifiApRunning', {
      iface: wifi.iface || '?',
      ssid: wifi.ssid || '?',
      route: wifi.route_profile || '?',
      subnet: wifi.subnet || '?',
    });
  } else if (availableCount === 0) {
    statusEl.textContent = t('feedback.wifiNoIface');
  } else {
    statusEl.textContent = t('ui.wifiApStatusIdle');
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

function renderBypassList(bypass = {}) {
  const tbody = document.getElementById('bypass-tbody');
  const activeUl = document.getElementById('bypass-active-ips');
  if (!tbody || !activeUl) return;

  tbody.innerHTML = '';
  const entries = bypass.entries || [];
  if (!entries.length) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="2" class="hint">${t('ui.bypassDesc')}</td>`;
    tbody.appendChild(tr);
  } else {
    entries.forEach((entry) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${entry}</code></td>
        <td class="action-cell">
          <button class="btn btn-danger tiny" data-bypass-remove="${entry}">Remove</button>
        </td>`;
      tbody.appendChild(tr);
    });
  }

  tbody.querySelectorAll('button[data-bypass-remove]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const entry = btn.dataset.bypassRemove;
      feedback('bypass-feedback', t('feedback.bypassRemoving'));
      const r = await controlAction('bypass_remove', { entry });
      feedback('bypass-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
      if (r.ok) setTimeout(refreshStatus, 500);
    });
  });

  activeUl.innerHTML = '';
  const activeIps = bypass.active_ips || [];
  if (!activeIps.length) {
    activeUl.textContent = t('geoUnavailable');
  } else {
    activeIps.forEach((ip) => {
      const li = document.createElement('li');
      li.innerHTML = `<code>${ip}</code>`;
      activeUl.appendChild(li);
    });
  }
}

/* ── Main status refresh ───────────────────── */
async function refreshStatus() {
  if (_statusPending) return;
  _statusPending = true;
  let data;
  try {
    data = await api('/api/status.php', null, 8000);
  } catch (err) {
    _statusPending = false;
    console.error('status refresh failed:', err);
    return;
  }
  _statusPending = false;

  // Overview
  const exitIpEl = document.getElementById('tor-exit-ip');
  if (exitIpEl) exitIpEl.textContent = data.tor_exit_ip || '—';
  const exitMeta = document.getElementById('tor-exit-meta');
  if (exitMeta && data.tor_exit_geoip?.available) {
    const g = data.tor_exit_geoip;
    exitMeta.textContent = [g.city, g.country].filter(Boolean).join(', ') || '';
  }

  const uptimeEl = document.getElementById('sys-uptime');
  if (uptimeEl) uptimeEl.textContent = data.system?.uptime_human || '—';
  const hostEl = document.getElementById('sys-hostname');
  if (hostEl) hostEl.textContent = `${data.system?.hostname || ''} • kernel ${data.system?.kernel || ''}`;

  const tb = data.tor_bootstrap || {};
  const tbEl = document.getElementById('tor-bootstrap');
  if (tbEl) tbEl.textContent = `${tb.percent ?? 0}%`;
  const tbPhase = document.getElementById('tor-bootstrap-phase');
  if (tbPhase) tbPhase.textContent = tb.phase || '';

  const ws = data.wan_state || 'unknown';
  const wanEl = document.getElementById('wan-state');
  const wanHint = document.getElementById('wan-hint');
  if (wanEl) {
    wanEl.textContent = (I18N[LANG].wan[ws] || ws);
    wanEl.style.color = ws === 'nowan' ? 'var(--red)' : (ws === 'failover' ? 'var(--yellow)' : 'var(--green)');
  }
  if (wanHint) wanHint.textContent = I18N[LANG].wanHint[ws] || '';

  const cpu = Number(data.cpu_percent || 0);
  const cpuVal = document.getElementById('cpu-val');
  if (cpuVal) cpuVal.textContent = cpu.toFixed(1);
  setBar('cpu-bar', cpu);

  const mem = data.memory || {};
  const memVal = document.getElementById('mem-val');
  if (memVal) memVal.textContent = Number(mem.percent || 0).toFixed(1);
  const memUsed = document.getElementById('mem-used');
  if (memUsed) memUsed.textContent = mem.used_mb ?? 0;
  const memTotal = document.getElementById('mem-total');
  if (memTotal) memTotal.textContent = mem.total_mb ?? 0;
  setBar('mem-bar', mem.percent || 0);

  const disk = data.system?.disk_root || {};
  const diskVal = document.getElementById('disk-val');
  if (diskVal) diskVal.textContent = Number(disk.percent || 0).toFixed(1);
  const diskUsed = document.getElementById('disk-used');
  if (diskUsed) diskUsed.textContent = disk.used_gb ?? 0;
  const diskTotal = document.getElementById('disk-total');
  if (diskTotal) diskTotal.textContent = disk.total_gb ?? 0;
  setBar('disk-bar', disk.percent || 0);

  const ph = data.pihole || {};
  const phTotal = document.getElementById('ph-total');
  const phBlocked = document.getElementById('ph-blocked');
  const phPct = document.getElementById('ph-pct');
  if (ph.available) {
    if (phTotal) phTotal.textContent = (ph.dns_queries_today || 0).toLocaleString();
    if (phBlocked) phBlocked.textContent = (ph.ads_blocked_today || 0).toLocaleString();
    if (phPct) phPct.textContent = `${Number(ph.ads_percentage || 0).toFixed(1)}%`;
  } else {
    if (phTotal) phTotal.textContent = 'N/A';
    if (phBlocked) phBlocked.textContent = 'N/A';
    if (phPct) phPct.textContent = 'N/A';
  }

  const clients = data.clients || { leases: [], count: 0 };
  const ovClients = document.getElementById('ov-clients');
  if (ovClients) ovClients.textContent = clients.count ?? 0;

  const ovVpn = document.getElementById('ov-vpn');
  if (ovVpn) {
    const vpn = data.vpn || {};
    ovVpn.textContent = vpn.connected ? 'Connected' : 'Disconnected';
    ovVpn.style.color = vpn.connected ? 'var(--green)' : 'var(--muted)';
  }

  const torRotation = Number(data.tor_rotation_interval_sec || 600);
  const curEl = document.getElementById('tor-rotation-current');
  if (curEl) curEl.value = `${torRotation}s`;
  const setEl = document.getElementById('tor-rotation-seconds');
  if (setEl && document.activeElement !== setEl) setEl.value = torRotation;

  // VPN profiles
  const profileSel = document.getElementById('vpn-profile-select');
  if (profileSel) {
    const current = profileSel.value;
    profileSel.innerHTML = `<option value="">${t('ui.selectOption')}</option>`;
    (data.vpn_profiles || []).forEach((p) => {
      const opt = document.createElement('option');
      opt.value = p;
      opt.textContent = p;
      if (p === current) opt.selected = true;
      profileSel.appendChild(opt);
    });
  }

  renderServices(data.service_details || {});
  renderInterfaces(data.network || {}, data.interfaces || {});
  renderClients(clients);
  renderWifiAp(data.wifi_ap || {});
  renderBypassList(data.bypass_list || {});
  updateGeoMap(data.tor_exit_geoip || {});
}

/* ── Event listeners ───────────────────────── */
document.getElementById('btn-new-circuit')?.addEventListener('click', async () => {
  feedback('router-feedback', '⏳ Requesting new circuit...');
  const r = await controlAction('tor_new_circuit');
  feedback('router-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-new-circuit-2')?.addEventListener('click', async () => {
  feedback('router-feedback', '⏳ Requesting new circuit...');
  const r = await controlAction('tor_new_circuit');
  feedback('router-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-restart-tor')?.addEventListener('click', async () => {
  feedback('router-feedback', '⏳ Restarting Tor...');
  const r = await controlAction('tor_restart');
  feedback('router-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-tor-rotation-save')?.addEventListener('click', async () => {
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
  document.getElementById('btn-tor-rotation-save')?.click();
}

document.getElementById('btn-rot-300')?.addEventListener('click', () => applyRotationPreset(300));
document.getElementById('btn-rot-600')?.addEventListener('click', () => applyRotationPreset(600));
document.getElementById('btn-rot-1800')?.addEventListener('click', () => applyRotationPreset(1800));
document.getElementById('btn-rot-3600')?.addEventListener('click', () => applyRotationPreset(3600));

document.getElementById('btn-firewall-reload')?.addEventListener('click', async () => {
  feedback('router-feedback', '⏳ Reloading firewall...');
  const r = await controlAction('firewall_reload');
  feedback('router-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-router-start')?.addEventListener('click', async () => {
  feedback('router-feedback', '⏳ Starting router...');
  const r = await controlAction('router_start');
  feedback('router-feedback', r.ok ? '✓ Router started' : `✗ ${r.message}`, !r.ok);
  if (r.ok) setTimeout(refreshStatus, 2000);
});

document.getElementById('btn-router-stop')?.addEventListener('click', async () => {
  feedback('router-feedback', '⏳ Stopping router...');
  const r = await controlAction('router_stop');
  feedback('router-feedback', r.ok ? '✓ Router stopped' : `✗ ${r.message}`, !r.ok);
  if (r.ok) setTimeout(refreshStatus, 2000);
});

document.getElementById('btn-router-restart')?.addEventListener('click', async () => {
  feedback('router-feedback', '⏳ Restarting router...');
  const r = await controlAction('router_restart');
  feedback('router-feedback', r.ok ? '✓ Router restarted' : `✗ ${r.message}`, !r.ok);
  if (r.ok) setTimeout(refreshStatus, 2500);
});

document.getElementById('btn-set-wan')?.addEventListener('click', async () => {
  const iface = document.getElementById('wan-select')?.value;
  feedback('wan-feedback', `⏳ Setting primary WAN to ${iface}...`);
  const r = await controlAction('wan_set_primary', { interface: iface });
  feedback('wan-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-vpn-connect')?.addEventListener('click', async () => {
  const profile = document.getElementById('vpn-profile-select')?.value;
  if (!profile) return feedback('vpn-feedback', t('feedback.profileFirst'), true);
  feedback('vpn-feedback', `⏳ Connecting ${profile}...`);
  const r = await controlAction('vpn_connect', { profile });
  feedback('vpn-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-vpn-disconnect')?.addEventListener('click', async () => {
  feedback('vpn-feedback', '⏳ Disconnecting VPN...');
  const r = await controlAction('vpn_disconnect');
  feedback('vpn-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-vpn-upload')?.addEventListener('click', async () => {
  const fileInput = document.getElementById('vpn-file-input');
  if (!fileInput?.files.length) return feedback('vpn-feedback', t('feedback.uploadFirst'), true);
  const formData = new FormData();
  formData.append('action', 'vpn_upload');
  formData.append('file', fileInput.files[0]);
  feedback('vpn-feedback', '⏳ Uploading profile...');
  const res = await fetch('/api/control.php', { method: 'POST', body: formData });
  const r = await res.json();
  feedback('vpn-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
  if (r.ok) fileInput.value = '';
});

document.getElementById('btn-wifi-ap-start')?.addEventListener('click', async () => {
  const ssid = (document.getElementById('wifi-ap-ssid')?.value || '').trim();
  const password = document.getElementById('wifi-ap-password')?.value || '';
  const route_profile = document.getElementById('wifi-ap-route')?.value || '10';
  const interfaceName = document.getElementById('wifi-ap-iface')?.value || '';

  if (!ssid || ssid.length > 32) return feedback('wifi-ap-feedback', t('feedback.wifiSsidRequired'), true);
  if (password.length < 8 || password.length > 63) return feedback('wifi-ap-feedback', t('feedback.wifiPasswordRequired'), true);

  feedback('wifi-ap-feedback', t('feedback.wifiStarting'));
  const r = await controlAction('wifi_ap_start', { ssid, password, route_profile, interface: interfaceName });
  feedback('wifi-ap-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
  if (r.ok) setTimeout(refreshStatus, 1500);
});

document.getElementById('btn-wifi-ap-stop')?.addEventListener('click', async () => {
  feedback('wifi-ap-feedback', t('feedback.wifiStopping'));
  const r = await controlAction('wifi_ap_stop');
  feedback('wifi-ap-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
  if (r.ok) setTimeout(refreshStatus, 1200);
});

document.getElementById('btn-load-logs')?.addEventListener('click', async () => {
  const service = document.getElementById('logs-service')?.value;
  feedback('logs-feedback', `⏳ Loading ${service} logs...`);
  const r = await controlAction('logs_get', { service, lines: 80 });
  if (r.ok) {
    document.getElementById('logs-output').textContent = r.logs || '(empty)';
    feedback('logs-feedback', '✓ Logs loaded');
  } else {
    feedback('logs-feedback', `✗ ${r.message}`, true);
  }
});

document.getElementById('btn-config-load')?.addEventListener('click', async () => {
  const config_key = document.getElementById('config-key')?.value;
  feedback('config-feedback', `⏳ Loading ${config_key}...`);
  const r = await controlAction('config_get', { config_key });
  if (r.ok) {
    document.getElementById('config-content').value = r.content || '';
    feedback('config-feedback', `✓ Loaded ${r.path}`);
  } else {
    feedback('config-feedback', `✗ ${r.message}`, true);
  }
});

document.getElementById('btn-config-save')?.addEventListener('click', async () => {
  const config_key = document.getElementById('config-key')?.value;
  const content = document.getElementById('config-content')?.value;
  const apply_action = document.getElementById('config-apply')?.value;
  feedback('config-feedback', `⏳ Saving ${config_key}...`);
  const r = await controlAction('config_set', { config_key, content, apply_action });
  feedback('config-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
});

document.getElementById('btn-trbl-check')?.addEventListener('click', async () => {
  feedback('trbl-feedback', t('feedback.diagRunning'));
  const r = await controlAction('troubleshoot_run');
  if (r.ok) {
    document.getElementById('trbl-output').textContent = r.output || '(empty)';
    feedback('trbl-feedback', t('feedback.diagDone'));
  } else {
    feedback('trbl-feedback', `✗ ${r.message}`, true);
  }
});

async function runTroubleshootFix(mode, label) {
  feedback('trbl-feedback', `⏳ ${label}...`);
  const r = await controlAction('troubleshoot_fix', { mode });
  const out = document.getElementById('trbl-output');
  if (out) out.textContent = r.output || r.message || '(no output)';
  feedback('trbl-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
  if (r.ok) setTimeout(refreshStatus, 2500);
}

document.getElementById('btn-trbl-fix-dns')?.addEventListener('click', () => runTroubleshootFix('dns', 'Fixing DNS/Tor chain'));
document.getElementById('btn-trbl-fix-firewall')?.addEventListener('click', () => runTroubleshootFix('firewall', 'Reapplying firewall'));
document.getElementById('btn-trbl-fix-stack')?.addEventListener('click', () => runTroubleshootFix('stack', 'Restarting router stack'));
document.getElementById('btn-trbl-fix-full')?.addEventListener('click', () => runTroubleshootFix('full', 'Running full recovery'));

document.getElementById('lang-en')?.addEventListener('click', () => {
  LANG = 'en';
  localStorage.setItem('tsr-lang', 'en');
  applyLangButtons();
  applyI18nUI();
  refreshStatus();
});

document.getElementById('lang-pt')?.addEventListener('click', () => {
  LANG = 'pt';
  localStorage.setItem('tsr-lang', 'pt');
  applyLangButtons();
  applyI18nUI();
  refreshStatus();
});

// Bypass listeners
document.getElementById('btn-bypass-add')?.addEventListener('click', async () => {
  const input = document.getElementById('bypass-entry');
  const entry = (input?.value || '').trim();
  if (!entry) {
    feedback('bypass-feedback', t('feedback.bypassEntryRequired'), true);
    return;
  }
  if (!/^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$|^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/.test(entry)) {
    feedback('bypass-feedback', t('feedback.bypassEntryInvalid'), true);
    return;
  }
  feedback('bypass-feedback', t('feedback.bypassAdding'));
  const r = await controlAction('bypass_add', { entry });
  feedback('bypass-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
  if (r.ok && input) {
    input.value = '';
    setTimeout(refreshStatus, 500);
  }
});

document.getElementById('btn-bypass-apply')?.addEventListener('click', async () => {
  feedback('bypass-feedback', t('feedback.bypassApplying'));
  const r = await controlAction('bypass_apply');
  feedback('bypass-feedback', r.ok ? `✓ ${r.message}` : `✗ ${r.message}`, !r.ok);
  if (r.ok) setTimeout(refreshStatus, 500);
});

document.getElementById('btn-pentest-refresh')?.addEventListener('click', () => {
  const frame = document.getElementById('pentest-frame');
  if (frame) frame.src = frame.src;
});

/* ── Init ──────────────────────────────────── */
initNavigation();
refreshStatus();
setInterval(refreshStatus, REFRESH_INTERVAL);
