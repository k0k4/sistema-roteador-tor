<?php
// =============================================================================
// /var/www/tor-router/api/control.php
// Executes control actions requested by the dashboard.
// =============================================================================

header('Content-Type: application/json');

$SCRIPTS = '/usr/local/bin/tor-router.d';
$TOR_ROUTER = '/usr/local/bin/tor-router';
$WIFI_AP_MANAGER = '/usr/local/bin/tor-router.d/wifi_ap_manager.sh';

$SERVICE_UNITS = [
    'tor'          => 'tor@default',
    'dnsmasq'      => 'dnsmasq',
    'nginx'        => 'nginx',
    'pihole'       => 'pihole-FTL',
    'dnscrypt'     => 'dnscrypt-proxy',
    'php_fpm'      => 'php8.4-fpm',
    'wan_failover' => 'wan-failover',
    'ssh'          => 'ssh',
];

$CONFIG_FILES = [
    'torrc'            => '/etc/tor/torrc',
    'dnsmasq'          => '/etc/dnsmasq.conf',
    'nginx_dashboard'  => '/etc/nginx/sites-available/tor-router',
    'firewall'         => '/usr/local/bin/firewall.sh',
    'wan_manager'      => '/usr/local/bin/tor-router.d/wan_manager.sh',
    'sshd_tor'         => '/etc/ssh/sshd_config.d/tor-access.conf',
    'pihole_toml'      => '/etc/pihole/pihole.toml',
];

function json_response(bool $ok, string $message, array $extra = []): void {
    echo json_encode(array_merge(['ok' => $ok, 'message' => $message], $extra));
    exit;
}

function run_cmd(string $cmd): array {
    exec($cmd . " 2>&1", $out, $rc);
    return [$rc === 0, trim(implode("\n", $out)), $rc];
}

function read_action(): string {
    if (isset($_GET['action']) && is_string($_GET['action'])) {
        return $_GET['action'];
    }
    if (isset($_POST['action']) && is_string($_POST['action'])) {
        return $_POST['action'];
    }
    $raw = file_get_contents('php://input');
    $body = json_decode($raw ?: '', true) ?? [];
    return is_string($body['action'] ?? null) ? $body['action'] : '';
}

function read_body(): array {
    $ct = $_SERVER['CONTENT_TYPE'] ?? '';
    if (str_starts_with($ct, 'application/json')) {
        return json_decode(file_get_contents('php://input'), true) ?? [];
    }
    return $_POST ?: [];
}

function wifi_iface_candidates(string $manager): array {
    [$ok, $out] = run_cmd("sudo " . escapeshellarg($manager) . " list");
    if (!$ok || $out === '') return [];
    $rows = preg_split('/\r?\n/', trim($out));
    $items = [];
    foreach ($rows as $row) {
        $parts = explode('|', trim($row));
        if (count($parts) < 3) continue;
        $items[] = [
            'iface' => $parts[0],
            'available' => ($parts[1] === '1'),
            'reason' => $parts[2],
        ];
    }
    return $items;
}

// Only accept POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    json_response(false, 'Method not allowed');
}

$body   = read_body();
$action = read_action();

switch ($action) {

    // ---- Tor: new circuit / restart ----
    case 'tor_new_circuit':
        [$ok, $msg] = run_cmd("sudo $SCRIPTS/new_tor_circuit.sh");
        json_response($ok, $msg ?: ($ok ? 'New circuit requested.' : 'Failed.'));
        break;

    case 'tor_restart':
        [$ok, $msg] = run_cmd("sudo /usr/bin/systemctl restart tor@default");
        json_response($ok, $ok ? 'Tor restarted.' : $msg);
        break;

    case 'tor_set_rotation_interval':
        $seconds = (int)($body['seconds'] ?? 600);
        if ($seconds < 10 || $seconds > 86400) {
            json_response(false, 'Interval must be between 10 and 86400 seconds.');
        }

        $torrc = '/etc/tor/torrc';
        if (!is_readable($torrc)) {
            json_response(false, 'Unable to read /etc/tor/torrc');
        }
        $content = file_get_contents($torrc);
        if ($content === false) {
            json_response(false, 'Unable to load torrc content.');
        }

        if (preg_match('/^MaxCircuitDirtiness\s+\d+/mi', $content)) {
            $newContent = preg_replace('/^MaxCircuitDirtiness\s+\d+/mi', "MaxCircuitDirtiness $seconds", $content);
        } else {
            $newContent = rtrim($content) . "\n\n# Tor circuit rotation interval (managed by dashboard)\nMaxCircuitDirtiness $seconds\n";
        }

        $tmp = tempnam('/tmp', 'torrc_');
        if ($tmp === false) {
            json_response(false, 'Failed creating temporary file.');
        }
        file_put_contents($tmp, $newContent);
        [$okInstall, $msgInstall] = run_cmd("sudo /usr/bin/install -m 0644 " . escapeshellarg($tmp) . " /etc/tor/torrc");
        @unlink($tmp);
        if (!$okInstall) {
            json_response(false, 'Failed writing torrc.', ['output' => $msgInstall]);
        }

        [$okRestart, $msgRestart] = run_cmd("sudo /usr/bin/systemctl restart tor@default");
        if (!$okRestart) {
            json_response(false, 'Interval saved but Tor restart failed.', ['output' => $msgRestart]);
        }
        json_response(true, "Tor rotation interval set to $seconds seconds.");
        break;

    // ---- VPN: connect / disconnect ----
    case 'vpn_connect':
        $profile = basename($body['profile'] ?? '');
        if (empty($profile)) {
            json_response(false, 'No profile specified.');
        }
        [$ok, $msg] = run_cmd("sudo $SCRIPTS/connect_vpn.sh " . escapeshellarg($profile));
        json_response($ok, $msg ?: ($ok ? 'VPN connected.' : 'VPN connection failed.'));
        break;

    case 'vpn_disconnect':
        [$ok, $msg] = run_cmd("sudo $SCRIPTS/disconnect_vpn.sh");
        json_response($ok, $ok ? 'VPN disconnected.' : $msg);
        break;

    // ---- VPN: upload profile ----
    case 'vpn_upload':
        $vpn_dir = '/etc/tor-router/vpn';
        if (!isset($_FILES['file'])) {
            json_response(false, 'No file uploaded.');
        }
        $fname = basename($_FILES['file']['name']);
        // Only allow .conf and .ovpn
        if (!preg_match('/\.(conf|ovpn)$/', $fname)) {
            json_response(false, 'Only .conf and .ovpn files allowed.');
        }
        $dest = "$vpn_dir/$fname";
        if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
            chmod($dest, 0600);
            json_response(true, "Profile '$fname' uploaded.");
        } else {
            json_response(false, 'Upload failed.');
        }
        break;

    // ---- Router lifecycle ----
    case 'router_start':
    case 'router_stop':
    case 'router_restart':
    case 'router_status':
        $sub = str_replace('router_', '', $action);
        [$ok, $msg] = run_cmd("sudo $TOR_ROUTER " . escapeshellarg($sub));
        json_response($ok, $ok ? "Router action '$sub' executed." : $msg, ['output' => $msg]);
        break;

    // ---- Service management ----
    case 'service_action':
        $service = (string)($body['service'] ?? '');
        $op = (string)($body['operation'] ?? '');
        if (!isset($SERVICE_UNITS[$service])) {
            json_response(false, 'Invalid service.');
        }
        if (!in_array($op, ['start', 'stop', 'restart'], true)) {
            json_response(false, 'Invalid operation.');
        }
        $unit = $SERVICE_UNITS[$service];
        [$ok, $msg] = run_cmd("sudo /usr/bin/systemctl $op " . escapeshellarg($unit));
        json_response($ok, $ok ? "$service $op successful." : $msg);
        break;

    // ---- WAN: set primary ----
    case 'wan_set_primary':
        $iface = $body['interface'] ?? 'eth0';
        if (!in_array($iface, ['eth0', 'wlan0'])) {
            json_response(false, 'Invalid interface.');
        }
        [$ok, $msg] = run_cmd("sudo $SCRIPTS/wan_manager.sh set-primary " . escapeshellarg($iface));
        json_response($ok, $msg ?: ($ok ? "Primary WAN set to $iface." : 'Failed.'));
        break;

    // ---- Wi-Fi AP router ----
    case 'wifi_ap_start':
        $ssid = trim((string)($body['ssid'] ?? ''));
        $password = (string)($body['password'] ?? '');
        $routeProfile = (string)($body['route_profile'] ?? '');
        $ifaceRequested = trim((string)($body['interface'] ?? ''));

        if ($ssid === '' || strlen($ssid) > 32) {
            json_response(false, 'SSID must be 1..32 characters.');
        }
        if (strlen($password) < 8 || strlen($password) > 63) {
            json_response(false, 'Wi-Fi password must be 8..63 characters.');
        }
        if (!in_array($routeProfile, ['10', '20', '30'], true)) {
            json_response(false, 'Invalid route profile. Use 10, 20 or 30.');
        }

        $candidates = wifi_iface_candidates($WIFI_AP_MANAGER);
        if (empty($candidates)) {
            json_response(false, 'No Wi-Fi interfaces detected.');
        }

        $selected = '';
        if ($ifaceRequested !== '') {
            foreach ($candidates as $c) {
                if ($c['iface'] === $ifaceRequested) {
                    if (!$c['available']) {
                        json_response(false, "Interface '$ifaceRequested' is not available ({$c['reason']}).");
                    }
                    $selected = $ifaceRequested;
                    break;
                }
            }
            if ($selected === '') {
                json_response(false, "Interface '$ifaceRequested' not found.");
            }
        } else {
            foreach ($candidates as $c) {
                if ($c['available']) {
                    $selected = $c['iface'];
                    break;
                }
            }
        }

        if ($selected === '') {
            json_response(false, 'No available Wi-Fi interface (all in WAN use).');
        }

        $cmd = "sudo " . escapeshellarg($WIFI_AP_MANAGER)
             . " start " . escapeshellarg($selected)
             . " " . escapeshellarg($ssid)
             . " " . escapeshellarg($password)
             . " " . escapeshellarg($routeProfile);
        [$ok, $msg] = run_cmd($cmd);
        json_response($ok, $ok ? "Wi-Fi AP started on $selected (profile $routeProfile)." : ($msg ?: 'Failed starting Wi-Fi AP.'), ['output' => $msg, 'interface' => $selected]);
        break;

    case 'wifi_ap_stop':
        [$ok, $msg] = run_cmd("sudo " . escapeshellarg($WIFI_AP_MANAGER) . " stop");
        json_response($ok, $ok ? 'Wi-Fi AP stopped.' : ($msg ?: 'Failed stopping Wi-Fi AP.'), ['output' => $msg]);
        break;

    // ---- Firewall: reload ----
    case 'firewall_reload':
        [$ok, $msg] = run_cmd("sudo /usr/local/bin/firewall.sh");
        json_response($ok, $ok ? 'Firewall reloaded.' : $msg);
        break;

    // ---- Troubleshoot helpers ----
    case 'troubleshoot_run':
        $checks = [];
        [$ok1, $o1] = run_cmd("systemctl is-active tor@default dnsmasq pihole-FTL dnscrypt-proxy 2>/dev/null");
        $checks[] = "Services (tor,dnsmasq,pihole,dnscrypt):\n" . $o1;

        [$ok2, $o2] = run_cmd("ss -tulnp | grep -E ':(53|5335|5053|9053|9040)\\b' || true");
        $checks[] = "Ports:\n" . $o2;

        [$ok3, $o3] = run_cmd("dig @127.0.0.1 -p 5053 cloudflare.com +short +time=3 +tries=1");
        $checks[] = "dnscrypt 127.0.0.1:5053:\n" . ($o3 ?: '(no response)');

        [$ok4, $o4] = run_cmd("dig @127.0.0.1 -p 5335 cloudflare.com +short +time=3 +tries=1");
        $checks[] = "Pi-hole 127.0.0.1:5335:\n" . ($o4 ?: '(no response)');

        [$ok5, $o5] = run_cmd("dig @192.168.30.1 -p 53 duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion +short +time=4 +tries=1");
        $checks[] = "Tor LAN DNS 192.168.30.1:53 (.onion):\n" . ($o5 ?: '(no response)');

        [$ok6, $o6] = run_cmd("grep 'Bootstrapped' /var/log/tor/tor.log | tail -3");
        $checks[] = "Tor bootstrap:\n" . ($o6 ?: '(no bootstrap entries)');

        json_response(true, 'Diagnostics complete.', ['output' => implode("\n\n", $checks)]);
        break;

    case 'troubleshoot_fix':
        $mode = (string)($body['mode'] ?? 'dns');
        $run_steps = function(array $commands): array {
            $output = [];
            foreach ($commands as $cmd) {
                [$ok, $msg] = run_cmd($cmd);
                $output[] = '$ ' . $cmd;
                if ($msg !== '') {
                    $output[] = $msg;
                }
                if (!$ok) {
                    return [false, implode("\n", $output)];
                }
            }
            return [true, implode("\n", $output)];
        };
        switch ($mode) {
            case 'dns':
                [$ok, $out] = $run_steps([
                    "sudo /usr/bin/systemctl restart dnscrypt-proxy",
                    "sudo /usr/bin/systemctl restart pihole-FTL",
                    "sudo /usr/bin/systemctl restart dnsmasq",
                    "sudo /usr/bin/systemctl restart tor@default",
                ]);
                json_response($ok, $ok ? 'DNS/Tor chain restarted.' : 'DNS/Tor chain recovery failed.', ['output' => $out]);
                break;
            case 'firewall':
                [$ok, $msg] = run_cmd("sudo /usr/local/bin/firewall.sh");
                json_response($ok, $ok ? 'Firewall reapplied.' : $msg, ['output' => $msg]);
                break;
            case 'stack':
                [$ok, $msg] = run_cmd("sudo /usr/local/bin/tor-router restart");
                json_response($ok, $ok ? 'Router stack restarted.' : $msg, ['output' => $msg]);
                break;
            case 'full':
                [$ok, $out] = $run_steps([
                    "sudo /usr/bin/systemctl restart tor@default",
                    "sudo /usr/bin/systemctl restart dnscrypt-proxy",
                    "sudo /usr/bin/systemctl restart pihole-FTL",
                    "sudo /usr/bin/systemctl restart dnsmasq",
                    "sudo /usr/bin/systemctl restart nginx",
                    "sudo /usr/bin/systemctl restart php8.4-fpm",
                    "sudo /usr/bin/systemctl restart wan-failover",
                    "sudo /usr/local/bin/firewall.sh",
                ]);
                json_response($ok, $ok ? 'Full recovery applied.' : 'Full recovery failed.', ['output' => $out]);
                break;
            default:
                json_response(false, 'Invalid troubleshoot mode.');
        }
        break;

    // ---- Logs ----
    case 'logs_get':
        $service = (string)($body['service'] ?? 'tor');
        $lines = (int)($body['lines'] ?? 50);
        $lines = max(10, min($lines, 300));
        $map = [
            'tor' => 'tor@default',
            'dnsmasq' => 'dnsmasq',
            'nginx' => 'nginx',
            'pihole' => 'pihole-FTL',
            'wan' => 'wan-failover',
            'router' => 'tor-router',
            'ssh' => 'ssh',
        ];
        if (!isset($map[$service])) {
            json_response(false, 'Invalid log target.');
        }
        [$ok, $msg] = run_cmd("sudo /usr/bin/journalctl -u " . escapeshellarg($map[$service]) . " -n $lines --no-pager");
        json_response($ok, $ok ? 'Logs loaded.' : 'Failed to read logs.', ['logs' => $msg]);
        break;

    // ---- Config read/save ----
    case 'config_get':
        $key = (string)($body['config_key'] ?? '');
        if (!isset($CONFIG_FILES[$key])) {
            json_response(false, 'Invalid config key.');
        }
        $path = $CONFIG_FILES[$key];
        if (!is_readable($path)) {
            json_response(false, "Config file not readable: $path");
        }
        $content = file_get_contents($path);
        json_response(true, 'Config loaded.', [
            'config_key' => $key,
            'path' => $path,
            'content' => $content === false ? '' : $content,
        ]);
        break;

    case 'config_set':
        $key = (string)($body['config_key'] ?? '');
        $content = (string)($body['content'] ?? '');
        $apply = (string)($body['apply_action'] ?? '');

        if (!isset($CONFIG_FILES[$key])) {
            json_response(false, 'Invalid config key.');
        }
        if (strlen($content) > 500000) {
            json_response(false, 'Config too large.');
        }

        $path = $CONFIG_FILES[$key];
        $dir = dirname($path);
        if (!is_dir($dir)) {
            json_response(false, "Config directory does not exist: $dir");
        }

        $backup = $path . '.bak.' . date('YmdHis');
        run_cmd("sudo /bin/cp " . escapeshellarg($path) . ' ' . escapeshellarg($backup));

        $tmp = tempnam('/tmp', 'trcfg_');
        if ($tmp === false) {
            json_response(false, 'Failed creating temp file.');
        }
        if (file_put_contents($tmp, $content) === false) {
            json_response(false, 'Failed writing temp config file.');
        }

        $mode = in_array($key, ['firewall', 'wan_manager'], true) ? '0755' : '0644';
        [$writeOk, $writeMsg] = run_cmd("sudo /usr/bin/install -m $mode " . escapeshellarg($tmp) . ' ' . escapeshellarg($path));
        @unlink($tmp);
        if (!$writeOk) {
            json_response(false, 'Failed replacing config file.', ['output' => $writeMsg]);
        }

        $applyOutput = '';
        if ($apply !== '') {
            $applyMap = [
                'restart_tor' => "sudo /usr/bin/systemctl restart tor@default",
                'restart_dnsmasq' => "sudo /usr/bin/systemctl restart dnsmasq",
                'reload_nginx' => "sudo /usr/bin/systemctl restart nginx",
                'restart_pihole' => "sudo /usr/bin/systemctl restart pihole-FTL",
                'apply_firewall' => "sudo /usr/local/bin/firewall.sh",
                'restart_wan' => "sudo /usr/bin/systemctl restart wan-failover",
                'restart_router' => "sudo /usr/local/bin/tor-router restart",
                'restart_ssh' => "sudo /usr/bin/systemctl restart ssh",
                'none' => '',
            ];
            if (!isset($applyMap[$apply])) {
                json_response(false, 'Invalid apply action.');
            }
            if ($applyMap[$apply] !== '') {
                [$applyOk, $applyOutput] = run_cmd($applyMap[$apply]);
                if (!$applyOk) {
                    json_response(false, 'Config saved but apply failed.', ['output' => $applyOutput, 'backup' => $backup]);
                }
            }
        }

        json_response(true, 'Config saved successfully.', ['backup' => $backup, 'output' => $applyOutput]);
        break;

    default:
        http_response_code(400);
        json_response(false, "Unknown action: $action");
}
