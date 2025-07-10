#!/bin/bash

# ============================================================================
# Script de Instalação do Roteador TOR
# Sistema: Linux Lite 7.4 / Ubuntu 24.04
# Autor: Manus AI
# Versão: 1.0
# ============================================================================

set -e  # Sair em caso de erro

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para log
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERRO] $1${NC}"
    exit 1
}

warning() {
    echo -e "${YELLOW}[AVISO] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Verificar se está rodando como root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root (sudo)"
fi

log "Iniciando instalação do Roteador TOR..."

# ============================================================================
# CONFIGURAÇÕES INICIAIS
# ============================================================================

# Interfaces de rede (ajustar conforme necessário)
INTERNET_INTERFACE="eth0"  # Interface conectada à internet
WIFI_INTERFACE="wlan0"     # Interface WiFi para hotspot
LAN_INTERFACE="eth1"       # Interface LAN para cabos

# Configurações da rede WiFi
WIFI_SSID="TOR_Router_Secure"
WIFI_PASSWORD="TorSecure2024!"
WIFI_CHANNEL="6"

# Configurações de rede interna
INTERNAL_NETWORK="192.168.100.0/24"
GATEWAY_IP="192.168.100.1"
DHCP_START="192.168.100.10"
DHCP_END="192.168.100.200"

# Diretórios
TOR_CONFIG_DIR="/etc/tor"
SCRIPTS_DIR="/opt/tor_router"
LOG_DIR="/var/log/tor_router"

log "Criando diretórios necessários..."
mkdir -p "$SCRIPTS_DIR"
mkdir -p "$LOG_DIR"

# ============================================================================
# ATUALIZAÇÃO DO SISTEMA
# ============================================================================

log "Atualizando sistema..."
apt update -y
apt upgrade -y

# ============================================================================
# INSTALAÇÃO DE PACOTES
# ============================================================================

log "Instalando pacotes necessários..."

# Primeiro, resolver conflitos de pacotes
log "Resolvendo conflitos de dependências..."
apt remove --purge -y iptables-persistent netfilter-persistent 2>/dev/null || true
apt autoremove -y

# Instalar pacotes essenciais sem conflitos
apt install -y \
    tor \
    tor-geoipdb \
    obfs4proxy \
    hostapd \
    dnsmasq \
    iptables \
    bridge-utils \
    wireless-tools \
    wpasupplicant \
    iw \
    rfkill \
    curl \
    wget \
    net-tools \
    htop \
    iftop \
    vnstat \
    speedtest-cli \
    python3 \
    python3-pip \
    python3-requests \
    python3-psutil \
    python3-netifaces \
    systemd-timesyncd \
    fail2ban \
    macchanger

# Configurar timesyncd em vez de ntp (mais moderno e sem conflitos)
log "Configurando sincronização de tempo..."
systemctl enable systemd-timesyncd
systemctl start systemd-timesyncd

# Configurar firewall manualmente em vez de ufw (evita conflitos)
log "Configurando firewall básico..."

# Instalar pacotes Python adicionais
pip3 install --upgrade pip
pip3 install requests psutil netifaces speedtest-cli stem

# ============================================================================
# CONFIGURAÇÃO DO TOR
# ============================================================================

log "Configurando Tor..."

# Backup da configuração original
cp /etc/tor/torrc /etc/tor/torrc.backup

# Criar nova configuração do Tor
cat > /etc/tor/torrc << 'EOF'
# Configuração do Roteador TOR
# Gerado automaticamente

# Configurações básicas
User debian-tor
PidFile /var/run/tor/tor.pid
Log notice file /var/log/tor/tor.log
Log notice syslog
DataDirectory /var/lib/tor

# Configurações de rede
SocksPort 9050
TransPort 9040
DNSPort 9053

# Configurações de transparência
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
AutomapHostsSuffixes .onion,.exit

# Configurações de segurança
AvoidDiskWrites 1
HardwareAccel 1
TestSocks 1
AllowNonRFC953Hostnames 0
ClientOnly 1
SafeLogging 1
MaxCircuitDirtiness 600
NewCircuitPeriod 30
MaxClientCircuitsPending 48
UseEntryGuards 1
EnforceDistinctSubnets 1

# Configurações de performance
CircuitBuildTimeout 60
CircuitIdleTimeout 1800
CircuitStreamTimeout 20
ClientBootstrapConsensusAuthorityDownloadInitialDelay 5
ClientBootstrapConsensusAuthorityOnlyDownloadInitialDelay 5

# Configurações de país (evitar países com censura)
ExitNodes {us},{ca},{de},{nl},{se},{ch},{no},{dk},{fi}
EntryNodes {us},{ca},{de},{nl},{se},{ch},{no},{dk},{fi}
StrictNodes 1

# Configurações de bridge (descomente se necessário)
# UseBridges 1
# ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
# Bridge obfs4 [IP]:[PORT] [FINGERPRINT] cert=[CERT] iat-mode=0

# Configurações de controle
ControlPort 9051
HashedControlPassword 16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C
CookieAuthentication 1
CookieAuthFileGroupReadable 1

# Configurações de isolamento
IsolateClientAuth 1
IsolateClientProtocol 1
IsolateDestAddr 1
IsolateDestPort 1
IsolateSOCKSAuth 1

# Configurações de DNS
ServerDNSResolvConfFile /etc/resolv.conf
ServerDNSAllowBrokenConfig 1
ServerDNSSearchDomains 0
ServerDNSDetectHijacking 1
ServerDNSTestAddresses 8.8.8.8,8.8.4.4,208.67.222.222,208.67.220.220

# Configurações de largura de banda
RelayBandwidthRate 0
RelayBandwidthBurst 0
MaxAdvertisedBandwidth 0

# Configurações de circuito
PathBiasCircThreshold 20
PathBiasNoticeRate 0.70
PathBiasWarnRate 0.50
PathBiasExtremeRate 0.30
PathBiasDropGuards 0
PathBiasScaleThreshold 200

# Configurações de entrada
GuardLifetime 1 month
NumEntryGuards 3
NumDirectoryGuards 3
UseGuardFraction 1

# Configurações de saída
ExitPolicy reject *:*
ExitPolicyRejectPrivate 1
ExitPolicyRejectLocalInterfaces 1

# Configurações de hidden services (se necessário)
# HiddenServiceDir /var/lib/tor/hidden_service/
# HiddenServicePort 80 127.0.0.1:80

# Configurações de logging
SafeLogging 1
LogTimeGranularity 1
TruncateLogFile 1

# Configurações de cliente
FetchDirInfoEarly 1
FetchDirInfoExtraEarly 1
FetchHidServDescriptors 1
FetchServerDescriptors 1
FetchUselessDescriptors 0
DownloadExtraInfo 0

# Configurações de consenso
FetchV3NetworkStatus 1
UseMicrodescriptors 1
DownloadExtraInfo 0

# Configurações de mapeamento de endereços
MapAddress 10.40.0.0/18 10.40.0.0/18
MapAddress 127.0.0.0/8 127.0.0.0/8
MapAddress 169.254.0.0/16 169.254.0.0/16
MapAddress 172.16.0.0/12 172.16.0.0/12
MapAddress 192.168.0.0/16 192.168.0.0/16
MapAddress 224.0.0.0/4 224.0.0.0/4
MapAddress 240.0.0.0/4 240.0.0.0/4

# Configurações de tempo
KeepalivePeriod 60
NewCircuitPeriod 30
MaxCircuitDirtiness 600
CircuitBuildTimeout 60

# Configurações de diretório
DirReqStatistics 0
DirPortFrontPage /etc/tor/tor-exit-notice.html
EOF

# Configurar permissões
chown debian-tor:debian-tor /etc/tor/torrc
chmod 644 /etc/tor/torrc

# ============================================================================
# CONFIGURAÇÃO DO HOSTAPD (WiFi Hotspot)
# ============================================================================

log "Configurando hostapd para WiFi..."

cat > /etc/hostapd/hostapd.conf << EOF
# Configuração do WiFi Hotspot TOR
interface=$WIFI_INTERFACE
driver=nl80211
ssid=$WIFI_SSID
hw_mode=g
channel=$WIFI_CHANNEL
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$WIFI_PASSWORD
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP

# Configurações de segurança
wpa_group_rekey=86400
wpa_strict_rekey=1
wpa_gmk_rekey=86400
wpa_ptk_rekey=600

# Configurações de performance
beacon_int=100
dtim_period=2
max_num_sta=50
rts_threshold=2347
fragm_threshold=2346

# Configurações de país
country_code=BR
ieee80211d=1
ieee80211h=1

# Configurações de QoS
wmm_enabled=1
wmm_ac_bk_cwmin=4
wmm_ac_bk_cwmax=10
wmm_ac_bk_aifs=7
wmm_ac_bk_txop_limit=0
wmm_ac_be_aifs=3
wmm_ac_be_cwmin=4
wmm_ac_be_cwmax=10
wmm_ac_be_txop_limit=0
wmm_ac_vi_aifs=2
wmm_ac_vi_cwmin=3
wmm_ac_vi_cwmax=4
wmm_ac_vi_txop_limit=94
wmm_ac_vo_aifs=2
wmm_ac_vo_cwmin=2
wmm_ac_vo_cwmax=3
wmm_ac_vo_txop_limit=47

# Configurações de log
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
EOF

# Configurar daemon do hostapd
echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' > /etc/default/hostapd

# ============================================================================
# CONFIGURAÇÃO DO DNSMASQ (DHCP)
# ============================================================================

log "Configurando dnsmasq..."

# Backup da configuração original
cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup

cat > /etc/dnsmasq.conf << EOF
# Configuração do DNSMASQ para Roteador TOR

# Interface de escuta
interface=$WIFI_INTERFACE,$LAN_INTERFACE
bind-interfaces

# Configurações de DHCP
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,12h
dhcp-option=3,$GATEWAY_IP
dhcp-option=6,$GATEWAY_IP

# Configurações de DNS
server=127.0.0.1#9053
no-resolv
no-poll
cache-size=1000
neg-ttl=3600
max-ttl=3600

# Configurações de segurança
bogus-priv
domain-needed
expand-hosts
local=/lan/
domain=lan
dhcp-authoritative

# Configurações de log
log-queries
log-dhcp
log-facility=/var/log/dnsmasq.log

# Configurações de performance
dns-forward-max=1000
cache-size=1000

# Bloquear domínios maliciosos (básico)
address=/doubleclick.net/127.0.0.1
address=/googleadservices.com/127.0.0.1
address=/googlesyndication.com/127.0.0.1
address=/facebook.com/127.0.0.1
address=/fbcdn.net/127.0.0.1
address=/google-analytics.com/127.0.0.1

# Configurações de DHCP estático (exemplos)
# dhcp-host=aa:bb:cc:dd:ee:ff,192.168.100.50,laptop
# dhcp-host=11:22:33:44:55:66,192.168.100.51,desktop

# Configurações de PXE (se necessário)
# dhcp-boot=pxelinux.0

# Configurações de IPv6 (desabilitado por segurança)
dhcp-option=option6:dns-server,[::]
EOF

# ============================================================================
# CONFIGURAÇÃO DE REDE
# ============================================================================

log "Configurando interfaces de rede..."

# Configurar interface WiFi
cat > /etc/systemd/network/10-wifi-hotspot.network << EOF
[Match]
Name=$WIFI_INTERFACE

[Network]
Address=$GATEWAY_IP/24
IPMasquerade=yes
IPForward=yes
DHCPServer=no
EOF

# Configurar interface LAN
cat > /etc/systemd/network/20-lan.network << EOF
[Match]
Name=$LAN_INTERFACE

[Network]
Address=$GATEWAY_IP/24
IPMasquerade=yes
IPForward=yes
DHCPServer=no
EOF

# Habilitar IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding=0' >> /etc/sysctl.conf
echo 'net.ipv6.conf.default.forwarding=0' >> /etc/sysctl.conf

# Aplicar configurações de sysctl
sysctl -p

# ============================================================================
# CONFIGURAÇÃO DO IPTABLES
# ============================================================================

log "Configurando iptables..."

# Script de configuração do iptables
cat > "$SCRIPTS_DIR/setup_iptables.sh" << 'EOF'
#!/bin/bash

# Configuração do iptables para Roteador TOR

# Limpar regras existentes
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X

# Políticas padrão
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Permitir loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Permitir conexões estabelecidas
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Permitir SSH (ajustar porta se necessário)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Permitir DHCP
iptables -A INPUT -p udp --dport 67:68 -j ACCEPT

# Permitir DNS
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT

# Permitir tráfego da rede interna
iptables -A INPUT -s 192.168.100.0/24 -j ACCEPT
iptables -A FORWARD -s 192.168.100.0/24 -j ACCEPT

# Redirecionar DNS para Tor
iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 53 -j REDIRECT --to-ports 9053
iptables -t nat -A PREROUTING -i eth1 -p udp --dport 53 -j REDIRECT --to-ports 9053

# Redirecionar tráfego TCP para Tor (exceto SSH)
iptables -t nat -A PREROUTING -i wlan0 -p tcp --syn -j REDIRECT --to-ports 9040
iptables -t nat -A PREROUTING -i eth1 -p tcp --syn -j REDIRECT --to-ports 9040

# Masquerade para internet
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Bloquear tráfego direto para internet (forçar Tor)
iptables -A FORWARD -i wlan0 -o eth0 -j DROP
iptables -A FORWARD -i eth1 -o eth0 -j DROP

# Permitir tráfego Tor
iptables -A OUTPUT -m owner --uid-owner debian-tor -j ACCEPT

# Log de tentativas de conexão bloqueadas
iptables -A INPUT -j LOG --log-prefix "BLOCKED INPUT: "
iptables -A FORWARD -j LOG --log-prefix "BLOCKED FORWARD: "

# Salvar regras
iptables-save > /etc/iptables/rules.v4
EOF

chmod +x "$SCRIPTS_DIR/setup_iptables.sh"

# ============================================================================
# CONFIGURAÇÃO DE SERVIÇOS
# ============================================================================

log "Configurando serviços..."

# Habilitar serviços
systemctl enable tor
systemctl enable hostapd
systemctl enable dnsmasq
systemctl enable systemd-networkd

# Desabilitar NetworkManager para evitar conflitos
systemctl disable NetworkManager
systemctl stop NetworkManager

# Configurar fail2ban
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

systemctl enable fail2ban

# ============================================================================
# CONFIGURAÇÃO DE LOGS
# ============================================================================

log "Configurando sistema de logs..."

# Configurar logrotate para logs do Tor
cat > /etc/logrotate.d/tor-router << 'EOF'
/var/log/tor_router/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}

/var/log/tor/tor.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 debian-tor debian-tor
    postrotate
        systemctl reload tor > /dev/null 2>&1 || true
    endscript
}
EOF

# ============================================================================
# CONFIGURAÇÃO DE SEGURANÇA ADICIONAL
# ============================================================================

log "Aplicando configurações de segurança..."

# Configurar firewall básico com iptables (sem ufw para evitar conflitos)
log "Configurando firewall com iptables..."

# Limpar regras existentes
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Políticas padrão
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Permitir loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Permitir conexões estabelecidas
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Permitir SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Permitir DHCP
iptables -A INPUT -p udp --dport 67:68 -j ACCEPT

# Permitir DNS
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT

# Salvar regras iptables
log "Salvando regras de firewall..."
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

# Criar script para restaurar regras na inicialização
cat > /etc/systemd/system/iptables-restore.service << 'EOF'
[Unit]
Description=Restore iptables rules
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl enable iptables-restore.service

# Configurar kernel parameters para segurança
cat >> /etc/sysctl.conf << 'EOF'

# Configurações de segurança para Roteador TOR
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=5
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
EOF

# ============================================================================
# FINALIZAÇÃO
# ============================================================================

log "Criando scripts de controle..."

# Script de inicialização
cat > "$SCRIPTS_DIR/start_tor_router.sh" << 'EOF'
#!/bin/bash

echo "Iniciando Roteador TOR..."

# Configurar interfaces
ip addr add 192.168.100.1/24 dev wlan0
ip addr add 192.168.100.1/24 dev eth1
ip link set wlan0 up
ip link set eth1 up

# Aplicar regras de iptables
/opt/tor_router/setup_iptables.sh

# Iniciar serviços
systemctl start tor
systemctl start hostapd
systemctl start dnsmasq

echo "Roteador TOR iniciado com sucesso!"
EOF

# Script de parada
cat > "$SCRIPTS_DIR/stop_tor_router.sh" << 'EOF'
#!/bin/bash

echo "Parando Roteador TOR..."

# Parar serviços
systemctl stop dnsmasq
systemctl stop hostapd
systemctl stop tor

# Limpar iptables
iptables -F
iptables -t nat -F
iptables -t mangle -F

echo "Roteador TOR parado!"
EOF

# Script de status
cat > "$SCRIPTS_DIR/status_tor_router.sh" << 'EOF'
#!/bin/bash

echo "=== Status do Roteador TOR ==="
echo

echo "Serviços:"
systemctl is-active tor && echo "✓ Tor: Ativo" || echo "✗ Tor: Inativo"
systemctl is-active hostapd && echo "✓ Hostapd: Ativo" || echo "✗ Hostapd: Inativo"
systemctl is-active dnsmasq && echo "✓ Dnsmasq: Ativo" || echo "✗ Dnsmasq: Inativo"

echo
echo "Conexões Tor:"
netstat -tlnp | grep :9050 && echo "✓ SOCKS proxy ativo" || echo "✗ SOCKS proxy inativo"
netstat -tlnp | grep :9040 && echo "✓ Trans proxy ativo" || echo "✗ Trans proxy inativo"
netstat -tlnp | grep :9053 && echo "✓ DNS proxy ativo" || echo "✗ DNS proxy inativo"

echo
echo "Interfaces de rede:"
ip addr show wlan0 | grep "inet " && echo "✓ WiFi configurado" || echo "✗ WiFi não configurado"
ip addr show eth1 | grep "inet " && echo "✓ LAN configurado" || echo "✗ LAN não configurado"

echo
echo "Clientes conectados:"
iw dev wlan0 station dump | grep Station | wc -l | xargs echo "WiFi:"
arp -a | grep "192.168.100" | wc -l | xargs echo "Total:"
EOF

# Tornar scripts executáveis
chmod +x "$SCRIPTS_DIR"/*.sh

log "Instalação concluída!"
info "Scripts criados em: $SCRIPTS_DIR"
info "Logs em: $LOG_DIR"
warning "IMPORTANTE: Reinicie o sistema antes de usar o roteador TOR"
warning "Execute: sudo $SCRIPTS_DIR/start_tor_router.sh para iniciar"

echo
echo "=== CONFIGURAÇÕES FINAIS ==="
echo "SSID WiFi: $WIFI_SSID"
echo "Senha WiFi: $WIFI_PASSWORD"
echo "Gateway: $GATEWAY_IP"
echo "Rede interna: $INTERNAL_NETWORK"
echo
echo "Para verificar status: sudo $SCRIPTS_DIR/status_tor_router.sh"
echo "Para parar: sudo $SCRIPTS_DIR/stop_tor_router.sh"
echo

log "Script de instalação finalizado com sucesso!"

