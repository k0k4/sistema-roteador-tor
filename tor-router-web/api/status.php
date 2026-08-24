<?php
// =============================================================================
// /var/www/tor-router/api/status.php
// Returns JSON with system status for the dashboard.
// =============================================================================

header('Content-Type: application/json');
header('Cache-Control: no-cache');

// Security: only allow requests from localhost (nginx proxies from LAN)
// The nginx config already enforces LAN-only access.

function service_status(string $name): string {
    exec("systemctl is-active " . escapeshellarg($name) . " 2>/dev/null", $out, $rc);
    return ($rc === 0) ? 'active' : 'inactive';
}

function service_details(string $name): array {
    exec("systemctl is-active " . escapeshellarg($name) . " 2>/dev/null", $activeOut, $activeRc);
    exec("systemctl is-enabled " . escapeshellarg($name) . " 2>/dev/null", $enabledOut, $enabledRc);
    exec("systemctl show " . escapeshellarg($name) . " -p SubState --value 2>/dev/null", $subOut, $subRc);

    return [
        'active'   => ($activeRc === 0) ? trim($activeOut[0] ?? 'inactive') : 'inactive',
        'enabled'  => ($enabledRc === 0) ? trim($enabledOut[0] ?? 'disabled') : 'disabled',
        'substate' => ($subRc === 0) ? trim($subOut[0] ?? 'unknown') : 'unknown',
    ];
}

function vpn_status(): array {
    $wg_ifaces = [];
    exec("wg show interfaces 2>/dev/null", $wg_ifaces);
    $openvpn_running = (shell_exec("pgrep -x openvpn 2>/dev/null") !== null);
    return [
        'wireguard_interfaces' => array_filter($wg_ifaces),
        'openvpn' => $openvpn_running ? 'active' : 'inactive',
        'connected' => (!empty($wg_ifaces) || $openvpn_running),
    ];
}

function tor_exit_ip(): string {
    $cacheFile = '/run/tor-router/tor-exit-ip.cache';
    $maxAgeSec = 120;

    $readCache = function() use ($cacheFile): ?array {
        if (!is_readable($cacheFile)) return null;
        $raw = @file_get_contents($cacheFile);
        if (!$raw) return null;
        $obj = json_decode($raw, true);
        return is_array($obj) ? $obj : null;
    };

    $writeCache = function(array $data) use ($cacheFile): void {
        @mkdir('/run/tor-router', 0755, true);
        @file_put_contents($cacheFile, json_encode($data));
    };

    $fetchLive = function() use ($writeCache): ?string {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => 'https://api.ipify.org?format=json',
            CURLOPT_PROXY          => 'socks5h://127.0.0.1:9050',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_CONNECTTIMEOUT => 3,
        ]);
        $res = curl_exec($ch);
        curl_close($ch);
        if ($res) {
            $data = json_decode($res, true);
            $ip = $data['ip'] ?? null;
            if ($ip) {
                $writeCache([
                    'ip'        => $ip,
                    'timestamp' => date('c'),
                    'source'    => 'ipify',
                ]);
                return $ip;
            }
        }
        return null;
    };

    $cached = $readCache();
    if (is_array($cached) && !empty($cached['ip'])) {
        $ts = strtotime($cached['timestamp'] ?? '0');
        $age = ($ts === false) ? PHP_INT_MAX : (time() - $ts);
        if ($age < $maxAgeSec) {
            return $cached['ip'];
        }
        // Cache is stale: try a fast live fetch first
        $live = $fetchLive();
        if ($live !== null) {
            return $live;
        }
        // Fallback to stale cache rather than showing unavailable
        return $cached['ip'];
    }

    // No cache: fetch live with longer timeout
    $live = $fetchLive();
    if ($live !== null) {
        return $live;
    }
    return 'unavailable';
}

function tor_exit_geoip(string $ip): array {
    $cacheFile = '/run/tor-router/geoip-cache.json';

    $readCache = function() use ($cacheFile): ?array {
        if (!is_readable($cacheFile)) return null;
        $raw = @file_get_contents($cacheFile);
        if (!$raw) return null;
        $obj = json_decode($raw, true);
        return is_array($obj) ? $obj : null;
    };

    // Always prefer the background-updated cache; never block the dashboard.
    $cached = $readCache();
    if (is_array($cached) && ($cached['available'] ?? false)) {
        // If the cached IP matches the current exit IP, return it fresh.
        // Otherwise still return the cached geo (it will update on next timer run).
        if (($cached['ip'] ?? '') === $ip) {
            return $cached;
        }
        $cached['cached'] = true;
        $cached['note'] = 'IP changed since last geo lookup';
        return $cached;
    }

    if ($ip === '' || $ip === 'unavailable' || $ip === 'unknown') {
        return ['available' => false];
    }

    // Last-resort synchronous lookup only when no cache exists at all.
    $url = 'https://ipwho.is/' . rawurlencode($ip);
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 4,
        CURLOPT_CONNECTTIMEOUT => 2,
    ]);
    $res = curl_exec($ch);
    curl_close($ch);
    if (!$res) {
        return ['available' => false, 'ip' => $ip];
    }

    $data = json_decode($res, true);
    if (!is_array($data) || !($data['success'] ?? false)) {
        return ['available' => false, 'ip' => $ip];
    }

    return [
        'available'  => true,
        'ip'         => $ip,
        'country'    => $data['country'] ?? '',
        'region'     => $data['region'] ?? '',
        'city'       => $data['city'] ?? '',
        'latitude'   => isset($data['latitude']) ? (float)$data['latitude'] : null,
        'longitude'  => isset($data['longitude']) ? (float)$data['longitude'] : null,
        'timezone'   => $data['timezone']['id'] ?? ($data['timezone'] ?? ''),
        'org'        => $data['connection']['org'] ?? '',
        'asn'        => $data['connection']['asn'] ?? '',
    ];
}

function tor_rotation_interval(): int {
    $default = 600;
    $torrc = '/etc/tor/torrc';
    if (!is_readable($torrc)) return $default;
    $lines = file($torrc, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    foreach ($lines as $line) {
        $line = trim($line);
        if (str_starts_with($line, '#')) continue;
        if (preg_match('/^MaxCircuitDirtiness\s+(\d+)/i', $line, $m)) {
            return max(10, min((int)$m[1], 86400));
        }
    }
    return $default;
}

function tor_bootstrap(): array {
    $log = @file('/var/log/tor/tor.log');
    if (!$log) {
        return ['percent' => 0, 'phase' => 'unknown', 'done' => false];
    }

    $tail = array_slice($log, -400);
    $percent = 0;
    $phase = 'starting';
    $done = false;

    foreach ($tail as $line) {
        if (preg_match('/Bootstrapped\s+(\d+)%\s+\(([^)]+)\)/', $line, $m)) {
            $percent = (int)$m[1];
            $phase = $m[2];
            $done = ($percent >= 100);
        }
    }

    return [
        'percent' => $percent,
        'phase'   => $phase,
        'done'    => $done,
    ];
}

function cpu_usage(): float {
    // Read two samples of /proc/stat for accurate CPU %
    $stat1 = file('/proc/stat')[0];
    usleep(100000); // 100ms sample
    $stat2 = file('/proc/stat')[0];

    $parse = function(string $line): array {
        $parts = preg_split('/\s+/', trim($line));
        array_shift($parts); // remove "cpu" label
        return array_map('intval', $parts);
    };

    $s1 = $parse($stat1);
    $s2 = $parse($stat2);

    $idle1 = $s1[3] + ($s1[4] ?? 0);
    $idle2 = $s2[3] + ($s2[4] ?? 0);
    $total1 = array_sum($s1);
    $total2 = array_sum($s2);

    $diff_total = $total2 - $total1;
    $diff_idle  = $idle2  - $idle1;

    return $diff_total > 0 ? round((($diff_total - $diff_idle) / $diff_total) * 100, 1) : 0.0;
}

function memory_usage(): array {
    $data = [];
    foreach (file('/proc/meminfo') as $line) {
        [$key, $val] = explode(':', $line, 2);
        $data[trim($key)] = (int) trim($val);
    }
    $total = $data['MemTotal'] ?? 0;
    $avail = $data['MemAvailable'] ?? 0;
    $used  = $total - $avail;
    return [
        'total_mb' => round($total / 1024),
        'used_mb'  => round($used  / 1024),
        'free_mb'  => round($avail / 1024),
        'percent'  => $total > 0 ? round(($used / $total) * 100, 1) : 0,
    ];
}

function system_overview(): array {
    $uptimeRaw = @file_get_contents('/proc/uptime');
    $uptimeSec = (int) floor((float) explode(' ', trim((string)$uptimeRaw))[0]);

    $days  = intdiv($uptimeSec, 86400);
    $hours = intdiv($uptimeSec % 86400, 3600);
    $mins  = intdiv($uptimeSec % 3600, 60);
    $uptimeHuman = sprintf('%dd %02dh %02dm', $days, $hours, $mins);

    $load = explode(' ', trim((string)@file_get_contents('/proc/loadavg')));
    $diskTotal = @disk_total_space('/');
    $diskFree  = @disk_free_space('/');
    $diskUsed  = ($diskTotal && $diskFree) ? ($diskTotal - $diskFree) : 0;
    $diskPct   = ($diskTotal > 0) ? round(($diskUsed / $diskTotal) * 100, 1) : 0.0;

    return [
        'hostname'       => gethostname() ?: 'unknown',
        'kernel'         => php_uname('r'),
        'uptime_sec'     => $uptimeSec,
        'uptime_human'   => $uptimeHuman,
        'loadavg'        => [
            '1m'  => (float)($load[0] ?? 0),
            '5m'  => (float)($load[1] ?? 0),
            '15m' => (float)($load[2] ?? 0),
        ],
        'disk_root'      => [
            'total_gb' => $diskTotal ? round($diskTotal / 1073741824, 2) : 0,
            'used_gb'  => $diskUsed ? round($diskUsed / 1073741824, 2) : 0,
            'free_gb'  => $diskFree ? round($diskFree / 1073741824, 2) : 0,
            'percent'  => $diskPct,
        ],
    ];
}

function interface_details(): array {
    $ifaces = ['eth0', 'wlan0', 'eth1', 'eth2', 'eth3'];
    $out = [];

    foreach ($ifaces as $iface) {
        $state = trim((string)@file_get_contents("/sys/class/net/$iface/operstate"));
        $carrier = trim((string)@file_get_contents("/sys/class/net/$iface/carrier"));
        $mtu = trim((string)@file_get_contents("/sys/class/net/$iface/mtu"));
        $mac = trim((string)@file_get_contents("/sys/class/net/$iface/address"));

        exec("ip -4 -o addr show dev " . escapeshellarg($iface) . " 2>/dev/null", $addrOut, $addrRc);
        $ipv4 = null;
        if ($addrRc === 0 && !empty($addrOut[0])) {
            if (preg_match('/inet\s+([0-9.]+\/\d+)/', $addrOut[0], $m)) {
                $ipv4 = $m[1];
            }
        }

        $out[$iface] = [
            'state'   => $state ?: 'unknown',
            'carrier' => ($carrier === '1'),
            'mtu'     => is_numeric($mtu) ? (int)$mtu : null,
            'mac'     => $mac ?: null,
            'ipv4'    => $ipv4,
        ];
    }

    return $out;
}

function default_routes(): array {
    exec("ip -4 route show default 2>/dev/null", $out);
    $routes = [];
    foreach ($out as $line) {
        if (preg_match('/default via ([0-9.]+) dev (\S+)(?: .*metric (\d+))?/', $line, $m)) {
            $routes[] = [
                'gateway' => $m[1],
                'dev'     => $m[2],
                'metric'  => isset($m[3]) ? (int)$m[3] : null,
            ];
        }
    }
    return $routes;
}

function network_stats(): array {
    $stats = [];
    $ifaces = ['eth0', 'wlan0', 'eth1', 'eth2', 'eth3'];
    foreach (file('/proc/net/dev') as $line) {
        $line = trim($line);
        if (!str_contains($line, ':')) continue;
        [$iface, $data] = explode(':', $line, 2);
        $iface = trim($iface);
        if (!in_array($iface, $ifaces)) continue;
        $fields = preg_split('/\s+/', trim($data));
        $stats[$iface] = [
            'rx_bytes' => (int)$fields[0],
            'tx_bytes' => (int)$fields[8],
            'rx_mb'    => round((int)$fields[0] / 1048576, 2),
            'tx_mb'    => round((int)$fields[8] / 1048576, 2),
        ];
    }
    return $stats;
}

function dhcp_clients(): array {
    $file = '/var/lib/misc/dnsmasq.leases';
    if (!is_readable($file)) {
        return ['count' => 0, 'leases' => []];
    }

    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $leases = [];

    foreach ($lines as $line) {
        $parts = preg_split('/\s+/', trim($line));
        if (count($parts) < 5) continue;

        [$expiry, $mac, $ip, $hostname] = [$parts[0], $parts[1], $parts[2], $parts[3]];
        $network = str_starts_with($ip, '192.168.10.') ? 'lan'
                 : (str_starts_with($ip, '192.168.20.') ? 'tor1'
                 : (str_starts_with($ip, '192.168.30.') ? 'tor2' : 'other'));

        $leases[] = [
            'ip'       => $ip,
            'mac'      => $mac,
            'hostname' => ($hostname === '*') ? '' : $hostname,
            'expiry'   => (int)$expiry,
            'network'  => $network,
        ];
    }

    usort($leases, fn($a, $b) => strcmp($a['ip'], $b['ip']));

    return [
        'count'  => count($leases),
        'leases' => $leases,
    ];
}

function recent_logs(): array {
    $units = [
        'tor' => 'tor@default',
        'dnsmasq' => 'dnsmasq',
        'nginx' => 'nginx',
        'pihole' => 'pihole-FTL',
        'wan' => 'wan-failover',
    ];
    $logs = [];
    foreach ($units as $key => $unit) {
        exec("sudo /usr/bin/journalctl -u " . escapeshellarg($unit) . " -n 12 --no-pager 2>/dev/null", $out, $rc);
        $logs[$key] = ($rc === 0) ? implode("\n", $out) : '';
    }
    return $logs;
}

function pihole_stats(): array {
    // Pi-hole v6 API on port 8080
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => 'http://127.0.0.1:8080/api/stats/summary',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 5,
    ]);
    $res = curl_exec($ch);
    curl_close($ch);
    if (!$res) return ['available' => false];
    $data = json_decode($res, true) ?? [];
    return [
        'available'          => true,
        'dns_queries_today'  => $data['queries']['total'] ?? $data['dns_queries_today'] ?? 0,
        'ads_blocked_today'  => $data['queries']['blocked'] ?? $data['ads_blocked_today'] ?? 0,
        'ads_percentage'     => $data['queries']['percent_blocked'] ?? $data['ads_percentage_today'] ?? 0,
    ];
}

function wan_state(): string {
    $f = '/run/tor-router/wan_state';
    return file_exists($f) ? trim(file_get_contents($f)) : 'unknown';
}

function wifi_ap_status(): array {
    $manager = '/usr/local/bin/tor-router.d/wifi_ap_manager.sh';
    $ifaces = [];
    foreach (glob('/sys/class/net/*') ?: [] as $path) {
        $iface = basename($path);
        if (is_dir("$path/wireless")) {
            $ifaces[] = $iface;
        }
    }
    sort($ifaces);

    exec("ip -4 route show default 2>/dev/null", $routeOut);
    $wanInUse = [];
    foreach ($routeOut as $line) {
        if (preg_match('/\bdev\s+(\S+)/', $line, $m)) {
            $wanInUse[$m[1]] = true;
        }
    }

    $interfaces = [];
    foreach ($ifaces as $iface) {
        $interfaces[] = [
            'name' => $iface,
            'used_as_wan' => isset($wanInUse[$iface]),
            'available' => !isset($wanInUse[$iface]),
        ];
    }

    $status = [
        'running' => false,
        'interfaces' => $interfaces,
    ];

    $stateFile = '/run/tor-router/wifi-ap.state';
    if (is_readable($stateFile)) {
        $raw = file($stateFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        $kv = [];
        foreach ($raw as $line) {
            if (!str_contains($line, '=')) continue;
            [$k, $v] = explode('=', $line, 2);
            $kv[trim($k)] = trim($v);
        }
        if (($kv['running'] ?? '') === '1') {
            $status['running'] = true;
            $status['iface'] = $kv['iface'] ?? '';
            $status['ssid'] = $kv['ssid'] ?? '';
            $status['route_profile'] = $kv['route'] ?? '';
            $status['subnet'] = $kv['subnet'] ?? '';
            $status['gateway'] = $kv['gateway'] ?? '';
        }
    }

    if (is_executable($manager)) {
        exec("sudo " . escapeshellarg($manager) . " status 2>/dev/null", $mgrOut, $mgrRc);
        if ($mgrRc === 0) {
            foreach ($mgrOut as $line) {
                if (!str_contains($line, '=')) continue;
                [$k, $v] = explode('=', $line, 2);
                if (trim($k) === 'processes_ok') {
                    $status['processes_ok'] = (trim($v) === '1');
                }
            }
        }
    }

    return $status;
}

function vpn_profiles(): array {
    $dir = '/etc/tor-router/vpn';
    if (!is_dir($dir)) return [];
    $files = glob("$dir/*.{conf,ovpn}", GLOB_BRACE) ?: [];
    return array_map('basename', $files);
}

function bypass_list(): array {
    $file = '/etc/tor-router/bypass.list';
    $entries = [];
    if (is_readable($file)) {
        foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) continue;
            $entries[] = $line;
        }
    }

    $activeIps = [];
    $ipsetOutput = [];
    $ipsetRc = -1;
    exec("sudo /sbin/ipset list tor-bypass-v4 2>/dev/null", $ipsetOutput, $ipsetRc);
    if ($ipsetRc === 0) {
        foreach ($ipsetOutput as $line) {
            if (preg_match('/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/', $line)) {
                $activeIps[] = trim($line);
            }
        }
    }

    return [
        'entries'    => $entries,
        'active_ips' => array_values(array_unique($activeIps)),
        'count'      => count($entries),
    ];
}

// === Build response ===
$exitIp = tor_exit_ip();
$response = [
    'services' => [
        'tor'      => service_status('tor'),
        'dnsmasq'  => service_status('dnsmasq'),
        'nginx'    => service_status('nginx'),
        'pihole'   => service_status('pihole-FTL'),
        'openvpn'  => service_status('openvpn'),
        'hostapd'  => service_status('hostapd'),
        'pentest'  => service_status('trs-pentest'),
    ],
    'service_details' => [
        'tor'         => service_details('tor@default'),
        'dnsmasq'     => service_details('dnsmasq'),
        'nginx'       => service_details('nginx'),
        'pihole'      => service_details('pihole-FTL'),
        'dnscrypt'    => service_details('dnscrypt-proxy'),
        'php_fpm'     => service_details('php8.4-fpm'),
        'wan_failover'=> service_details('wan-failover'),
        'router'      => service_details('tor-router'),
        'ssh'         => service_details('ssh'),
        'hostapd'     => service_details('hostapd'),
        'pentest'     => service_details('trs-pentest'),
    ],
    'vpn'         => vpn_status(),
    'vpn_profiles'=> vpn_profiles(),
    'tor_exit_ip' => $exitIp,
    'tor_exit_geoip' => tor_exit_geoip($exitIp),
    'tor_bootstrap' => tor_bootstrap(),
    'tor_rotation_interval_sec' => tor_rotation_interval(),
    'cpu_percent' => cpu_usage(),
    'system'      => system_overview(),
    'memory'      => memory_usage(),
    'network'     => network_stats(),
    'interfaces'  => interface_details(),
    'routes'      => default_routes(),
    'clients'     => dhcp_clients(),
    'pihole'      => pihole_stats(),
    'wan_state'   => wan_state(),
    'wifi_ap'     => wifi_ap_status(),
    'bypass_list' => bypass_list(),
    'recent_logs' => recent_logs(),
    'timestamp'   => time(),
];

echo json_encode($response, JSON_PRETTY_PRINT);
