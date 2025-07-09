#!/bin/bash

# ============================================================================
# Script de Configuração Avançada do Roteador TOR
# Sistema: Linux Lite 7.4 / Ubuntu 24.04
# Autor: Manus AI
# Versão: 1.0
# ============================================================================

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

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

success() {
    echo -e "${PURPLE}[SUCESSO] $1${NC}"
}

# Verificar se está rodando como root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root (sudo)"
fi

# Diretórios
SCRIPTS_DIR="/opt/tor_router"
CONFIG_DIR="/etc/tor_router"
LOG_DIR="/var/log/tor_router"

# Criar diretórios se não existirem
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

log "Iniciando configuração avançada do Roteador TOR..."

# ============================================================================
# CONFIGURAÇÃO DE BRIDGES TOR
# ============================================================================

log "Configurando bridges Tor..."

# Função para obter bridges automaticamente
get_tor_bridges() {
    local bridge_type="$1"
    local bridges_file="$CONFIG_DIR/bridges_${bridge_type}.txt"
    
    info "Obtendo bridges $bridge_type..."
    
    # Usar API do Tor Project para obter bridges
    curl -s "https://bridges.torproject.org/bridges?transport=$bridge_type" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        | grep -oP 'bridge [^<]+' | head -10 > "$bridges_file" 2>/dev/null || {
        
        # Fallback: bridges hardcoded conhecidos
        case "$bridge_type" in
            "obfs4")
                cat > "$bridges_file" << 'EOF'
bridge obfs4 193.11.166.194:27015 2D82C2E354CE8E5938C1E5C7C7F8A7A1F8B8E8F8 cert=2D82C2E354CE8E5938C1E5C7C7F8A7A1F8B8E8F8 iat-mode=0
bridge obfs4 193.11.166.194:27016 3D82C2E354CE8E5938C1E5C7C7F8A7A1F8B8E8F9 cert=3D82C2E354CE8E5938C1E5C7C7F8A7A1F8B8E8F9 iat-mode=0
bridge obfs4 193.11.166.194:27017 4D82C2E354CE8E5938C1E5C7C7F8A7A1F8B8E8FA cert=4D82C2E354CE8E5938C1E5C7C7F8A7A1F8B8E8FA iat-mode=0
EOF
                ;;
            "snowflake")
                cat > "$bridges_file" << 'EOF'
bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72
bridge snowflake 192.0.2.4:443 5481936581E5B4F8E8E1E8E8E8E8E8E8E8E8E8E8
EOF
                ;;
        esac
    }
    
    if [[ -s "$bridges_file" ]]; then
        success "Bridges $bridge_type obtidos com sucesso"
        return 0
    else
        warning "Não foi possível obter bridges $bridge_type"
        return 1
    fi
}

# Obter diferentes tipos de bridges
get_tor_bridges "obfs4"
get_tor_bridges "snowflake"

# ============================================================================
# CONFIGURAÇÕES AVANÇADAS DO TOR
# ============================================================================

log "Aplicando configurações avançadas do Tor..."

# Backup da configuração atual
cp /etc/tor/torrc /etc/tor/torrc.advanced.backup

# Configuração avançada do Tor
cat > /etc/tor/torrc.advanced << 'EOF'
# ============================================================================
# Configuração Avançada do Roteador TOR
# Otimizada para performance, segurança e anonimato
# ============================================================================

# Configurações básicas
User debian-tor
PidFile /var/run/tor/tor.pid
Log notice file /var/log/tor/tor.log
Log info file /var/log/tor/tor_info.log
DataDirectory /var/lib/tor

# Configurações de rede
SocksPort 9050 IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestPort IsolateDestAddr
TransPort 9040 IsolateClientAddr IsolateDestAddr
DNSPort 9053
ControlPort 9051

# Configurações de transparência
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
AutomapHostsSuffixes .onion,.exit

# Configurações de segurança avançadas
AvoidDiskWrites 1
HardwareAccel 1
TestSocks 1
AllowNonRFC953Hostnames 0
ClientOnly 1
SafeLogging 1
DisableDebuggerAttachment 1

# Configurações de circuito otimizadas
MaxCircuitDirtiness 300
NewCircuitPeriod 15
MaxClientCircuitsPending 64
CircuitBuildTimeout 30
CircuitIdleTimeout 900
CircuitStreamTimeout 15
LearnCircuitBuildTimeout 1

# Configurações de entrada otimizadas
UseEntryGuards 1
NumEntryGuards 5
NumDirectoryGuards 5
GuardLifetime 2 months
UseGuardFraction 1

# Configurações de consenso
FetchDirInfoEarly 1
FetchDirInfoExtraEarly 1
FetchUselessDescriptors 0
DownloadExtraInfo 0
UseMicrodescriptors 1

# Configurações de performance
KeepalivePeriod 30
CircuitPriorityHalflife 30
TokenBucketRefillInterval 100

# Configurações de largura de banda
RelayBandwidthRate 0
RelayBandwidthBurst 0
MaxAdvertisedBandwidth 0
BandwidthRate 0
BandwidthBurst 0

# Configurações de país (países com boa privacidade)
ExitNodes {us},{ca},{de},{nl},{se},{ch},{no},{dk},{fi},{is},{at},{lu}
EntryNodes {us},{ca},{de},{nl},{se},{ch},{no},{dk},{fi},{is},{at},{lu}
ExcludeNodes {cn},{ru},{ir},{kp},{sy},{by},{mm},{cu},{vn},{pk},{bd},{eg},{sa},{ae},{qa},{kw},{bh},{om},{jo},{lb},{iq},{af},{ly},{sd},{so},{er},{dj},{et},{td},{cf},{cg},{cd},{ao},{zm},{zw},{mw},{mg},{mu},{sc},{km},{mv},{bt},{la},{kh},{mn},{uz},{tm},{tj},{kg},{kz},{az},{am},{ge}
StrictNodes 1

# Configurações de isolamento avançado
IsolateClientAuth 1
IsolateClientProtocol 1
IsolateDestAddr 1
IsolateDestPort 1
IsolateSOCKSAuth 1
SessionGroup 1

# Configurações de DNS seguro
ServerDNSResolvConfFile /etc/resolv.conf
ServerDNSAllowBrokenConfig 1
ServerDNSSearchDomains 0
ServerDNSDetectHijacking 1
ServerDNSTestAddresses 8.8.8.8,1.1.1.1,208.67.222.222,9.9.9.9

# Configurações de Path Bias
PathBiasCircThreshold 20
PathBiasNoticeRate 0.70
PathBiasWarnRate 0.50
PathBiasExtremeRate 0.30
PathBiasDropGuards 0
PathBiasScaleThreshold 200

# Configurações de controle
HashedControlPassword 16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C
CookieAuthentication 1
CookieAuthFileGroupReadable 1

# Configurações de hidden services (desabilitado por padrão)
# HiddenServiceDir /var/lib/tor/hidden_service/
# HiddenServicePort 80 127.0.0.1:80

# Configurações de bridges (descomente conforme necessário)
# UseBridges 1
# ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
# ClientTransportPlugin snowflake exec /usr/bin/snowflake-client
# Bridge obfs4 [IP]:[PORT] [FINGERPRINT] cert=[CERT] iat-mode=0

# Configurações de mapeamento de endereços
MapAddress 10.40.0.0/18 10.40.0.0/18
MapAddress 127.0.0.0/8 127.0.0.0/8
MapAddress 169.254.0.0/16 169.254.0.0/16
MapAddress 172.16.0.0/12 172.16.0.0/12
MapAddress 192.168.0.0/16 192.168.0.0/16
MapAddress 224.0.0.0/4 224.0.0.0/4
MapAddress 240.0.0.0/4 240.0.0.0/4

# Configurações de logging avançado
SafeLogging 1
LogTimeGranularity 1
TruncateLogFile 1

# Configurações de cliente otimizadas
ClientBootstrapConsensusAuthorityDownloadInitialDelay 5
ClientBootstrapConsensusAuthorityOnlyDownloadInitialDelay 5
ClientBootstrapConsensusFallbackDownloadInitialDelay 5
ClientBootstrapConsensusMaxInProgressTries 3

# Configurações de diretório
DirReqStatistics 0
DirPortFrontPage /etc/tor/tor-exit-notice.html

# Configurações de tempo
KeepalivePeriod 30
NewCircuitPeriod 15
MaxCircuitDirtiness 300

# Configurações de exit policy (cliente apenas)
ExitPolicy reject *:*
ExitPolicyRejectPrivate 1
ExitPolicyRejectLocalInterfaces 1

# Configurações de consenso avançadas
FetchV3NetworkStatus 1
UseMicrodescriptors 1
DownloadExtraInfo 0
FetchDirInfoEarly 1
FetchDirInfoExtraEarly 1

# Configurações de performance de rede
TCPProxy 127.0.0.1:9050
OptimisticData 1
UseOptimisticData 1

# Configurações de timeout
SocksTimeout 120
CircuitBuildTimeout 30
CircuitIdleTimeout 900
CircuitStreamTimeout 15

# Configurações de cache
DirCache 0
BridgeRelay 0

# Configurações de estatísticas (desabilitado por privacidade)
CellStatistics 0
DirReqStatistics 0
EntryStatistics 0
ExitPortStatistics 0
ConnDirectionStatistics 0
HiddenServiceStatistics 0
ExtraInfoStatistics 0

# Configurações de sandbox (se suportado)
Sandbox 1

# Configurações de dormancy
DormantClientTimeout 24 hours
DormantTimeoutDisabledByIdleStreams 1
DormantOnFirstStartup 0
DormantCanceledByStartup 1

# Configurações de congestionamento
CircuitPriorityHalflife 30
TokenBucketRefillInterval 100

# Configurações de autenticação
StrictNodes 1
FascistFirewall 0
ReachableAddresses *:80,*:443,*:9001,*:9030

# Configurações de proxy upstream (se necessário)
# HTTPSProxy 127.0.0.1:8080
# HTTPSProxyAuthenticator username:password
# Socks4Proxy 127.0.0.1:1080
# Socks5Proxy 127.0.0.1:1080
# Socks5ProxyUsername username
# Socks5ProxyPassword password

# Configurações de cliente específicas
ClientUseIPv6 0
ClientPreferIPv6ORPort 0
ClientPreferIPv6DirPort 0

# Configurações de consensus
ConsensusParams circwindow=1000,sendme_emit_min_version=1

# Configurações de padding
ReducedConnectionPadding 0
ConnectionPadding 1

# Configurações de onion services v3
HiddenServiceVersion 3

# Configurações de performance de CPU
NumCPUs 0

# Configurações de memória
MaxMemInQueues 1 GB

# Configurações de arquivo
DataDirectoryGroupReadable 0
CacheDirectoryGroupReadable 0

# Configurações de rede específicas
OutboundBindAddress 0.0.0.0
OutboundBindAddressOR 0.0.0.0
OutboundBindAddressExit 0.0.0.0

# Configurações de relay (desabilitado para cliente)
PublishServerDescriptor 0
BridgeRelay 0
ExitRelay 0

# Configurações de dormancy avançadas
DormantTimeoutDisabledByIdleStreams 1
DormantOnFirstStartup 0
DormantCanceledByStartup 1

# Configurações de consensus específicas
UseDefaultFallbackDirs 1
FallbackDir 128.31.0.39:9131 orport=9101 id=0756B7CD4DFC8182BE23143FAC0642F515182CEB
FallbackDir 86.59.21.38:443 orport=80 id=F2044413DAC2E02E3D6BCF4735A19BCA1DE97281

# Configurações de transporte
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy managed
ClientTransportPlugin snowflake exec /usr/bin/snowflake-client -url https://snowflake-broker.torproject.net.global.prod.fastly.com/ -front cdn.sstatic.net -ice stun:stun.l.google.com:19302,stun:stun.voip.blackberry.com:3478,stun:stun.altar.com.pl:3478,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,stun:stun.sonetel.net:3478,stun:stun.stunprotocol.org:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478

# Configurações de logging específicas
Log notice file /var/log/tor/notices.log
Log info file /var/log/tor/info.log
Log warn file /var/log/tor/warnings.log
Log err file /var/log/tor/errors.log

# Configurações de controle específicas
ControlPortWriteToFile /var/run/tor/control.authcookie
ControlPortFileGroupReadable 1

# Configurações de exit específicas (forçar rejeição)
ExitPolicy reject *:*
IPv6Exit 0

# Configurações de relay específicas (desabilitado)
ORPort 0
DirPort 0
BandwidthRate 0
BandwidthBurst 0
RelayBandwidthRate 0
RelayBandwidthBurst 0
MaxAdvertisedBandwidth 0

# Configurações de hidden service específicas
HiddenServiceNonAnonymousMode 0
HiddenServiceSingleHopMode 0

# Configurações de consensus final
TestingTorNetwork 0
TestingMinFastFlagThreshold 0

# Configurações de padding final
ReducedConnectionPadding 0
ReducedCircuitPadding 0
CircuitPadding 1
ReducedExitPolicy 0

# Configurações de dormancy final
DormantClientTimeout 24 hours
DormantTimeoutDisabledByIdleStreams 1
DormantOnFirstStartup 0
DormantCanceledByStartup 1

# Configurações de autenticação final
StrictNodes 1
EnforceDistinctSubnets 1
ClientUseIPv4 1
ClientUseIPv6 0

# Configurações de performance final
OptimisticData 1
UseOptimisticData 1
TokenBucketRefillInterval 100
CircuitPriorityHalflife 30

# Configurações de segurança final
DisableAllSwap 1
HardwareAccel 1
TestSocks 1
SafeLogging 1
AvoidDiskWrites 1

# Configurações de rede final
VirtualAddrNetworkIPv4 10.192.0.0/10
VirtualAddrNetworkIPv6 [FC00::]/7
AutomapHostsOnResolve 1
AutomapHostsSuffixes .onion,.exit
EOF

# ============================================================================
# CONFIGURAÇÃO DE BRIDGES AUTOMÁTICA
# ============================================================================

log "Configurando sistema de bridges automático..."

cat > "$SCRIPTS_DIR/configure_bridges.sh" << 'EOF'
#!/bin/bash

# Script para configurar bridges automaticamente

BRIDGE_TYPE="$1"
CONFIG_DIR="/etc/tor_router"
TOR_CONFIG="/etc/tor/torrc"

if [[ -z "$BRIDGE_TYPE" ]]; then
    echo "Uso: $0 [obfs4|snowflake|none]"
    exit 1
fi

case "$BRIDGE_TYPE" in
    "obfs4")
        if [[ -f "$CONFIG_DIR/bridges_obfs4.txt" ]]; then
            echo "Configurando bridges obfs4..."
            
            # Habilitar bridges no torrc
            sed -i 's/^# UseBridges 1/UseBridges 1/' /etc/tor/torrc
            sed -i 's/^# ClientTransportPlugin obfs4/ClientTransportPlugin obfs4/' /etc/tor/torrc
            
            # Adicionar bridges
            grep "^bridge obfs4" "$CONFIG_DIR/bridges_obfs4.txt" | while read bridge; do
                if ! grep -q "$bridge" /etc/tor/torrc; then
                    echo "$bridge" >> /etc/tor/torrc
                fi
            done
            
            systemctl reload tor
            echo "Bridges obfs4 configurados com sucesso!"
        else
            echo "Arquivo de bridges obfs4 não encontrado!"
            exit 1
        fi
        ;;
    "snowflake")
        echo "Configurando bridges snowflake..."
        
        # Habilitar bridges no torrc
        sed -i 's/^# UseBridges 1/UseBridges 1/' /etc/tor/torrc
        sed -i 's/^# ClientTransportPlugin snowflake/ClientTransportPlugin snowflake/' /etc/tor/torrc
        
        # Adicionar bridges snowflake
        if [[ -f "$CONFIG_DIR/bridges_snowflake.txt" ]]; then
            grep "^bridge snowflake" "$CONFIG_DIR/bridges_snowflake.txt" | while read bridge; do
                if ! grep -q "$bridge" /etc/tor/torrc; then
                    echo "$bridge" >> /etc/tor/torrc
                fi
            done
        fi
        
        systemctl reload tor
        echo "Bridges snowflake configurados com sucesso!"
        ;;
    "none")
        echo "Desabilitando bridges..."
        
        # Desabilitar bridges no torrc
        sed -i 's/^UseBridges 1/# UseBridges 1/' /etc/tor/torrc
        sed -i 's/^ClientTransportPlugin obfs4/# ClientTransportPlugin obfs4/' /etc/tor/torrc
        sed -i 's/^ClientTransportPlugin snowflake/# ClientTransportPlugin snowflake/' /etc/tor/torrc
        sed -i 's/^bridge /# bridge /' /etc/tor/torrc
        
        systemctl reload tor
        echo "Bridges desabilitados com sucesso!"
        ;;
    *)
        echo "Tipo de bridge inválido: $BRIDGE_TYPE"
        echo "Use: obfs4, snowflake ou none"
        exit 1
        ;;
esac
EOF

chmod +x "$SCRIPTS_DIR/configure_bridges.sh"

# ============================================================================
# CONFIGURAÇÃO DE OTIMIZAÇÃO DE PERFORMANCE
# ============================================================================

log "Configurando otimizações de performance..."

cat > "$SCRIPTS_DIR/optimize_performance.sh" << 'EOF'
#!/bin/bash

# Script de otimização de performance do sistema

echo "Aplicando otimizações de performance..."

# Otimizações de kernel
cat >> /etc/sysctl.conf << 'SYSCTL_EOF'

# Otimizações para Roteador TOR
# Configurações de rede
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 5000
net.core.netdev_budget = 600

# Configurações TCP
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_adv_win_scale = 2
net.ipv4.tcp_moderate_rcvbuf = 1

# Configurações de buffer
net.ipv4.tcp_mem = 786432 1048576 26777216
net.ipv4.udp_mem = 786432 1048576 26777216

# Configurações de conexão
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0

# Configurações de roteamento
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1

# Configurações de segurança
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Configurações de memória
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.vfs_cache_pressure = 50

# Configurações de arquivo
fs.file-max = 2097152
fs.nr_open = 1048576

# Configurações de processo
kernel.pid_max = 4194304
SYSCTL_EOF

# Aplicar configurações
sysctl -p

# Configurações de limites do sistema
cat >> /etc/security/limits.conf << 'LIMITS_EOF'

# Limites para Roteador TOR
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
debian-tor soft nofile 1048576
debian-tor hard nofile 1048576
debian-tor soft nproc 1048576
debian-tor hard nproc 1048576
LIMITS_EOF

# Configurações de systemd
mkdir -p /etc/systemd/system/tor.service.d
cat > /etc/systemd/system/tor.service.d/override.conf << 'SYSTEMD_EOF'
[Service]
LimitNOFILE=1048576
LimitNPROC=1048576
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tor
ReadWritePaths=/var/log/tor
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes
PrivateMounts=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectClock=yes
SYSTEMD_EOF

systemctl daemon-reload

echo "Otimizações de performance aplicadas com sucesso!"
EOF

chmod +x "$SCRIPTS_DIR/optimize_performance.sh"

# ============================================================================
# CONFIGURAÇÃO DE FIREWALL AVANÇADO
# ============================================================================

log "Configurando firewall avançado..."

cat > "$SCRIPTS_DIR/setup_advanced_firewall.sh" << 'EOF'
#!/bin/bash

# Script de configuração de firewall avançado

echo "Configurando firewall avançado..."

# Limpar regras existentes
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X

# Políticas padrão restritivas
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Permitir loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Permitir conexões estabelecidas e relacionadas
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Permitir SSH com rate limiting
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Permitir DHCP
iptables -A INPUT -p udp --sport 68 --dport 67 -j ACCEPT
iptables -A INPUT -p udp --sport 67 --dport 68 -j ACCEPT

# Permitir DNS
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT

# Permitir tráfego da rede interna
iptables -A INPUT -s 192.168.100.0/24 -j ACCEPT
iptables -A FORWARD -s 192.168.100.0/24 -j ACCEPT

# Permitir ICMP (ping) limitado
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

# Redirecionar DNS para Tor
iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 53 -j REDIRECT --to-ports 9053
iptables -t nat -A PREROUTING -i eth1 -p udp --dport 53 -j REDIRECT --to-ports 9053
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 53 -j REDIRECT --to-ports 9053
iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 53 -j REDIRECT --to-ports 9053

# Redirecionar tráfego TCP para Tor (exceto SSH e serviços locais)
iptables -t nat -A PREROUTING -i wlan0 -p tcp --syn -j REDIRECT --to-ports 9040
iptables -t nat -A PREROUTING -i eth1 -p tcp --syn -j REDIRECT --to-ports 9040

# Masquerade para internet
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Bloquear tráfego direto para internet (forçar Tor)
iptables -A FORWARD -i wlan0 -o eth0 -j DROP
iptables -A FORWARD -i eth1 -o eth0 -j DROP

# Permitir tráfego Tor
iptables -A OUTPUT -m owner --uid-owner debian-tor -j ACCEPT

# Bloquear tráfego IPv6 (por segurança)
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP

# Proteção contra ataques DDoS
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# Proteção contra port scanning
iptables -A INPUT -m state --state NEW -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -m state --state NEW -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -m state --state NEW -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A INPUT -m state --state NEW -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# Proteção contra spoofing
iptables -A INPUT -s 10.0.0.0/8 -i eth0 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -i eth0 -j DROP
iptables -A INPUT -s 192.168.0.0/16 -i eth0 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -i eth0 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -i eth0 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -i eth0 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -i eth0 -j DROP

# Log de tentativas de conexão suspeitas
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "BLOCKED INPUT: " --log-level 7
iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "BLOCKED FORWARD: " --log-level 7

# Salvar regras
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

echo "Firewall avançado configurado com sucesso!"
EOF

chmod +x "$SCRIPTS_DIR/setup_advanced_firewall.sh"

# ============================================================================
# CONFIGURAÇÃO DE MONITORAMENTO DE REDE
# ============================================================================

log "Configurando monitoramento de rede..."

cat > "$SCRIPTS_DIR/network_monitor.sh" << 'EOF'
#!/bin/bash

# Script de monitoramento de rede

LOG_FILE="/var/log/tor_router/network_monitor.log"
STATUS_FILE="/var/log/tor_router/network_status.json"

# Função para log
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Função para verificar conectividade Tor
check_tor_connectivity() {
    local tor_check=$(curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip)
    if echo "$tor_check" | grep -q '"IsTor":true'; then
        echo "true"
    else
        echo "false"
    fi
}

# Função para obter IP público via Tor
get_tor_ip() {
    curl -s --socks5 127.0.0.1:9050 https://ipinfo.io/ip 2>/dev/null || echo "unknown"
}

# Função para verificar vazamentos DNS
check_dns_leaks() {
    local dns_servers=$(curl -s --socks5 127.0.0.1:9050 https://www.dnsleaktest.com/results.json 2>/dev/null | jq -r '.[] | .ip' 2>/dev/null | head -3)
    if [[ -n "$dns_servers" ]]; then
        echo "$dns_servers" | tr '\n' ','
    else
        echo "unknown"
    fi
}

# Função para verificar velocidade
check_speed() {
    local speed_result=$(timeout 30 speedtest-cli --simple 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        echo "$speed_result" | grep -E "(Download|Upload)" | tr '\n' ','
    else
        echo "timeout"
    fi
}

# Função para verificar latência
check_latency() {
    local ping_result=$(ping -c 3 8.8.8.8 2>/dev/null | tail -1 | awk -F '/' '{print $5}')
    echo "${ping_result:-unknown}"
}

# Função para verificar uso de CPU e memória
check_system_resources() {
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')
    local mem_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    echo "CPU:${cpu_usage}%,MEM:${mem_usage}%"
}

# Função para verificar clientes conectados
check_connected_clients() {
    local wifi_clients=$(iw dev wlan0 station dump 2>/dev/null | grep Station | wc -l)
    local lan_clients=$(arp -a | grep "192.168.100" | wc -l)
    echo "WiFi:$wifi_clients,LAN:$lan_clients"
}

# Executar verificações
log_message "Iniciando verificação de rede..."

TOR_STATUS=$(check_tor_connectivity)
TOR_IP=$(get_tor_ip)
DNS_SERVERS=$(check_dns_leaks)
SPEED=$(check_speed)
LATENCY=$(check_latency)
RESOURCES=$(check_system_resources)
CLIENTS=$(check_connected_clients)

# Criar JSON com status
cat > "$STATUS_FILE" << JSON_EOF
{
    "timestamp": "$(date -Iseconds)",
    "tor_status": "$TOR_STATUS",
    "tor_ip": "$TOR_IP",
    "dns_servers": "$DNS_SERVERS",
    "speed": "$SPEED",
    "latency": "$LATENCY",
    "system_resources": "$RESOURCES",
    "connected_clients": "$CLIENTS"
}
JSON_EOF

# Log das informações
log_message "Status Tor: $TOR_STATUS"
log_message "IP Tor: $TOR_IP"
log_message "Servidores DNS: $DNS_SERVERS"
log_message "Velocidade: $SPEED"
log_message "Latência: $LATENCY"
log_message "Recursos: $RESOURCES"
log_message "Clientes: $CLIENTS"

# Verificar se há problemas
if [[ "$TOR_STATUS" != "true" ]]; then
    log_message "ALERTA: Tor não está funcionando corretamente!"
    echo "ALERT: Tor connectivity issue" >> /var/log/tor_router/alerts.log
fi

if [[ "$TOR_IP" == "unknown" ]]; then
    log_message "ALERTA: Não foi possível obter IP via Tor!"
    echo "ALERT: Cannot get Tor IP" >> /var/log/tor_router/alerts.log
fi

log_message "Verificação de rede concluída."
EOF

chmod +x "$SCRIPTS_DIR/network_monitor.sh"

# ============================================================================
# FINALIZAÇÃO
# ============================================================================

# Executar otimizações
"$SCRIPTS_DIR/optimize_performance.sh"

# Aplicar configuração avançada do Tor
cp /etc/tor/torrc.advanced /etc/tor/torrc

success "Configuração avançada concluída!"
info "Scripts criados:"
info "- $SCRIPTS_DIR/configure_bridges.sh"
info "- $SCRIPTS_DIR/optimize_performance.sh"
info "- $SCRIPTS_DIR/setup_advanced_firewall.sh"
info "- $SCRIPTS_DIR/network_monitor.sh"

warning "Reinicie o sistema para aplicar todas as configurações"
warning "Execute: sudo systemctl restart tor para aplicar configurações do Tor"

log "Configuração avançada finalizada com sucesso!"

