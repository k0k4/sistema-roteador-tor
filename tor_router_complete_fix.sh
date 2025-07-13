#!/bin/bash

# ============================================================================
# SISTEMA ROTEADOR TOR - CORREÇÃO COMPLETA E CONFIGURAÇÃO AUTOMÁTICA
# ============================================================================
# Detecta automaticamente 4 interfaces (1 WAN + 3 LAN) + WiFi
# Configura bridge TOR para todas as interfaces LAN
# Corrige todos os problemas identificados
# ============================================================================

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Variáveis globais
SCRIPT_DIR="/opt/sistema-roteador-tor"
TOR_ROUTER_DIR="/opt/tor_router"
BACKUP_DIR="/opt/tor_router_backup_$(date +%Y%m%d_%H%M%S)"
CONFIG_FILE="/opt/tor_router_config.conf"

# Interfaces detectadas
WAN_INTERFACE=""
LAN_INTERFACES=()
WIFI_INTERFACE=""
BRIDGE_NAME="br-tor"

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERRO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCESSO]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[AVISO]${NC} $1"
}

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

header() {
    echo
    echo -e "${CYAN}============================================================================${NC}"
    echo -e "${CYAN}                    $1${NC}"
    echo -e "${CYAN}============================================================================${NC}"
    echo
}

# Função para detectar interface WAN (com internet)
detect_wan_interface() {
    log "Detectando interface WAN (internet)..."
    
    # Procurar por interface com rota padrão
    local wan_iface=$(ip route show default | head -1 | awk '{print $5}' 2>/dev/null || true)
    
    if [[ -n "$wan_iface" && "$wan_iface" != "lo" ]]; then
        # Verificar se tem conectividade
        if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
            WAN_INTERFACE="$wan_iface"
            success "Interface WAN detectada: $WAN_INTERFACE"
            return 0
        fi
    fi
    
    # Fallback: procurar por interface ethernet com IP e conectividade
    for iface in $(ls /sys/class/net/ | grep -E '^(eth|enp|ens|eno)'); do
        if [[ -d "/sys/class/net/$iface" && "$iface" != "lo" ]]; then
            if ip addr show "$iface" | grep -q "inet.*scope global"; then
                if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
                    WAN_INTERFACE="$iface"
                    success "Interface WAN detectada: $WAN_INTERFACE"
                    return 0
                fi
            fi
        fi
    done
    
    error "Interface WAN não detectada!"
    return 1
}

# Função para detectar interfaces LAN
detect_lan_interfaces() {
    log "Detectando interfaces LAN..."
    
    LAN_INTERFACES=()
    
    # Procurar por todas as interfaces ethernet exceto a WAN
    for iface in $(ls /sys/class/net/ | grep -E '^(eth|enp|ens|eno)' | sort); do
        if [[ -d "/sys/class/net/$iface" && "$iface" != "lo" && "$iface" != "$WAN_INTERFACE" ]]; then
            LAN_INTERFACES+=("$iface")
            info "Interface LAN detectada: $iface"
        fi
    done
    
    if [[ ${#LAN_INTERFACES[@]} -eq 0 ]]; then
        error "Nenhuma interface LAN detectada!"
        return 1
    fi
    
    success "Total de interfaces LAN detectadas: ${#LAN_INTERFACES[@]}"
    return 0
}

# Função para detectar interface WiFi
detect_wifi_interface() {
    log "Detectando interface WiFi..."
    
    # Procurar por interfaces WiFi
    for iface in $(ls /sys/class/net/ | grep -E '^(wlan|wlp|wlx)'); do
        if [[ -d "/sys/class/net/$iface" ]]; then
            # Verificar se é interface WiFi
            if [[ -d "/sys/class/net/$iface/wireless" ]] || iw dev "$iface" info >/dev/null 2>&1; then
                WIFI_INTERFACE="$iface"
                success "Interface WiFi detectada: $WIFI_INTERFACE"
                return 0
            fi
        fi
    done
    
    error "Interface WiFi não detectada!"
    return 1
}

# Função para criar backup
create_backup() {
    log "Criando backup das configurações..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup dos scripts
    if [[ -d "$TOR_ROUTER_DIR" ]]; then
        cp -r "$TOR_ROUTER_DIR"/* "$BACKUP_DIR/" 2>/dev/null || true
    fi
    
    # Backup das configurações
    [[ -f "/etc/hostapd/hostapd.conf" ]] && cp "/etc/hostapd/hostapd.conf" "$BACKUP_DIR/"
    [[ -f "/etc/dnsmasq.conf" ]] && cp "/etc/dnsmasq.conf" "$BACKUP_DIR/"
    [[ -d "/etc/netplan" ]] && cp -r "/etc/netplan" "$BACKUP_DIR/"
    
    success "Backup criado em: $BACKUP_DIR"
}

# Função para limpar configurações conflitantes
cleanup_configs() {
    log "Limpando configurações conflitantes..."
    
    # Parar serviços
    systemctl stop tor hostapd dnsmasq 2>/dev/null || true
    
    # Limpar netplan duplicados
    rm -f /etc/netplan/50-cloud-init.yaml.backup* 2>/dev/null || true
    rm -f /etc/netplan/*NM-* 2>/dev/null || true
    
    # Remover bridge existente se houver
    ip link delete "$BRIDGE_NAME" 2>/dev/null || true
    
    success "Configurações conflitantes removidas"
}

# Função para criar bridge LAN
create_lan_bridge() {
    log "Criando bridge LAN para interfaces TOR..."
    
    # Criar bridge
    ip link add name "$BRIDGE_NAME" type bridge
    ip link set dev "$BRIDGE_NAME" up
    
    # Configurar IP do bridge
    ip addr add 192.168.100.1/24 dev "$BRIDGE_NAME"
    
    # Adicionar interfaces LAN ao bridge
    for iface in "${LAN_INTERFACES[@]}"; do
        # Configurar interface
        ip link set dev "$iface" up
        ip link set dev "$iface" master "$BRIDGE_NAME"
        info "Interface $iface adicionada ao bridge"
    done
    
    success "Bridge LAN criado: $BRIDGE_NAME"
}

# Função para configurar hostapd
configure_hostapd() {
    log "Configurando hostapd..."
    
    cat > /etc/hostapd/hostapd.conf << EOF
# Configuração do WiFi Hotspot TOR - Sistema K0K4
interface=$WIFI_INTERFACE
driver=nl80211
ssid=TOR-K0K4-Network
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0

# Configurações WPA2
wpa=2
wpa_passphrase=TorSecure2024!
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

    success "Hostapd configurado"
}

# Função para configurar dnsmasq
configure_dnsmasq() {
    log "Configurando dnsmasq..."
    
    cat > /etc/dnsmasq.conf << EOF
# Configuração do DNSMASQ para Roteador TOR - Sistema K0K4

# Interfaces de escuta
interface=$WIFI_INTERFACE,$BRIDGE_NAME
bind-interfaces

# Configurações de DHCP
dhcp-range=192.168.100.10,192.168.100.200,255.255.255.0,12h
dhcp-option=3,192.168.100.1
dhcp-option=6,192.168.100.1

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
address=/google-analytics.com/127.0.0.1

# Configurações de IPv6 (desabilitado por segurança)
dhcp-option=option6:dns-server,[::]
EOF

    success "Dnsmasq configurado"
}

# Função para configurar iptables
configure_iptables() {
    log "Configurando iptables..."
    
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
    
    # Permitir SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Permitir DNS e DHCP
    iptables -A INPUT -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -p tcp --dport 53 -j ACCEPT
    iptables -A INPUT -p udp --dport 67 -j ACCEPT
    
    # Permitir tráfego da rede interna
    iptables -A INPUT -s 192.168.100.0/24 -j ACCEPT
    iptables -A FORWARD -s 192.168.100.0/24 -j ACCEPT
    
    # NAT para internet via TOR
    iptables -t nat -A POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE
    
    # Redirecionar tráfego para TOR
    iptables -t nat -A PREROUTING -i "$WIFI_INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 9040
    iptables -t nat -A PREROUTING -i "$WIFI_INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port 9040
    iptables -t nat -A PREROUTING -i "$BRIDGE_NAME" -p tcp --dport 80 -j REDIRECT --to-port 9040
    iptables -t nat -A PREROUTING -i "$BRIDGE_NAME" -p tcp --dport 443 -j REDIRECT --to-port 9040
    
    # Salvar regras
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    
    success "Iptables configurado"
}

# Função para salvar configuração
save_config() {
    log "Salvando configuração..."
    
    cat > "$CONFIG_FILE" << EOF
# Configuração do Sistema Roteador TOR - K0K4
# Gerado automaticamente em: $(date)

# Interfaces detectadas
WAN_INTERFACE="$WAN_INTERFACE"
WIFI_INTERFACE="$WIFI_INTERFACE"
BRIDGE_NAME="$BRIDGE_NAME"

# Interfaces LAN (bridge)
LAN_INTERFACES=($(printf '"%s" ' "${LAN_INTERFACES[@]}"))

# Configurações de rede
INTERNAL_NETWORK="192.168.100.0/24"
GATEWAY_IP="192.168.100.1"
DHCP_RANGE="192.168.100.10,192.168.100.200"

# Configurações WiFi
WIFI_SSID="TOR-K0K4-Network"
WIFI_PASSWORD="TorSecure2024!"
WIFI_CHANNEL="6"

# Informações do sistema
HOSTNAME="$(hostname)"
KERNEL="$(uname -r)"
DISTRO="$(lsb_release -d 2>/dev/null | cut -f2 || echo 'Unknown')"
CREATED="$(date)"
EOF

    success "Configuração salva em: $CONFIG_FILE"
}

# Função para criar scripts corrigidos
create_corrected_scripts() {
    log "Criando scripts corrigidos..."
    
    mkdir -p "$TOR_ROUTER_DIR"
    
    # Script de início
    cat > "$TOR_ROUTER_DIR/start_tor_router.sh" << 'EOF'
#!/bin/bash

# Carregar configuração
source /opt/tor_router_config.conf

echo "Iniciando Roteador TOR - Sistema K0K4..."
echo "WAN: $WAN_INTERFACE"
echo "WiFi: $WIFI_INTERFACE"
echo "Bridge LAN: $BRIDGE_NAME"

# Criar bridge se não existir
if ! ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
    ip link add name "$BRIDGE_NAME" type bridge
    ip link set dev "$BRIDGE_NAME" up
    ip addr add 192.168.100.1/24 dev "$BRIDGE_NAME"
    
    # Adicionar interfaces LAN ao bridge
    for iface in "${LAN_INTERFACES[@]}"; do
        ip link set dev "$iface" up
        ip link set dev "$iface" master "$BRIDGE_NAME"
    done
fi

# Configurar interface WiFi
ip link set dev "$WIFI_INTERFACE" up

# Aplicar regras de firewall
/opt/tor_router/setup_iptables.sh

# Iniciar serviços
systemctl start tor
systemctl start hostapd
systemctl start dnsmasq

echo "Roteador TOR iniciado!"
echo "SSID: $WIFI_SSID"
echo "Senha: $WIFI_PASSWORD"
echo "Gateway: 192.168.100.1"
EOF

    # Script de parada
    cat > "$TOR_ROUTER_DIR/stop_tor_router.sh" << 'EOF'
#!/bin/bash

echo "Parando Roteador TOR..."

# Parar serviços
systemctl stop dnsmasq
systemctl stop hostapd
systemctl stop tor

# Remover bridge
source /opt/tor_router_config.conf
if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
    for iface in "${LAN_INTERFACES[@]}"; do
        ip link set dev "$iface" nomaster
    done
    ip link delete "$BRIDGE_NAME"
fi

echo "Roteador TOR parado!"
EOF

    # Script de status
    cat > "$TOR_ROUTER_DIR/status_tor_router.sh" << 'EOF'
#!/bin/bash

source /opt/tor_router_config.conf

echo "=== STATUS DO ROTEADOR TOR - SISTEMA K0K4 ==="
echo
echo "INTERFACES:"
echo "WAN: $WAN_INTERFACE"
echo "WiFi: $WIFI_INTERFACE"
echo "Bridge LAN: $BRIDGE_NAME"
echo

echo "STATUS DOS SERVIÇOS:"
echo -n "TOR: "
systemctl is-active tor
echo -n "HOSTAPD: "
systemctl is-active hostapd
echo -n "DNSMASQ: "
systemctl is-active dnsmasq
echo

echo "INTERFACE WAN ($WAN_INTERFACE):"
ip addr show "$WAN_INTERFACE" | grep -E "(inet|ether)" | sed 's/^/    /'
echo

echo "INTERFACE WIFI ($WIFI_INTERFACE):"
ip addr show "$WIFI_INTERFACE" | grep -E "(inet|ether)" | sed 's/^/    /'
echo "Status: $(cat /sys/class/net/$WIFI_INTERFACE/operstate)"
echo

echo "BRIDGE LAN ($BRIDGE_NAME):"
if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
    ip addr show "$BRIDGE_NAME" | grep -E "(inet|ether)" | sed 's/^/    /'
    echo "Interfaces no bridge:"
    for iface in "${LAN_INTERFACES[@]}"; do
        if [[ -f "/sys/class/net/$iface/master" ]]; then
            echo "    ✓ $iface"
        else
            echo "    ✗ $iface"
        fi
    done
else
    echo "    Bridge não existe"
fi
echo

echo "CONECTIVIDADE TOR:"
if curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip >/dev/null 2>&1; then
    echo "✓ TOR conectado"
else
    echo "✗ TOR não conectado"
fi
echo

echo "DISPOSITIVOS CONECTADOS:"
if command -v iw >/dev/null 2>&1; then
    echo "WiFi: $(iw dev "$WIFI_INTERFACE" station dump 2>/dev/null | grep Station | wc -l)"
else
    echo "WiFi: N/A"
fi
EOF

    # Script de iptables
    cat > "$TOR_ROUTER_DIR/setup_iptables.sh" << 'EOF'
#!/bin/bash

source /opt/tor_router_config.conf

echo "Configurando firewall..."

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

# Permitir SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Permitir DNS e DHCP
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --dport 67 -j ACCEPT

# Permitir tráfego da rede interna
iptables -A INPUT -s 192.168.100.0/24 -j ACCEPT
iptables -A FORWARD -s 192.168.100.0/24 -j ACCEPT

# NAT para internet
iptables -t nat -A POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE

# Redirecionar tráfego para TOR
iptables -t nat -A PREROUTING -i "$WIFI_INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 9040
iptables -t nat -A PREROUTING -i "$WIFI_INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port 9040
iptables -t nat -A PREROUTING -i "$BRIDGE_NAME" -p tcp --dport 80 -j REDIRECT --to-port 9040
iptables -t nat -A PREROUTING -i "$BRIDGE_NAME" -p tcp --dport 443 -j REDIRECT --to-port 9040

# Salvar regras
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

echo "Firewall configurado!"
EOF

    # Tornar scripts executáveis
    chmod +x "$TOR_ROUTER_DIR"/*.sh
    
    success "Scripts corrigidos criados"
}

# Função para configurar inicialização automática
configure_autostart() {
    log "Configurando inicialização automática..."
    
    # Criar serviço systemd
    cat > /etc/systemd/system/tor-router.service << EOF
[Unit]
Description=TOR Router Service - Sistema K0K4
After=network.target systemd-networkd.service
Wants=network.target

[Service]
Type=oneshot
ExecStart=/opt/tor_router/start_tor_router.sh
ExecStop=/opt/tor_router/stop_tor_router.sh
RemainAfterExit=yes
User=root

[Install]
WantedBy=multi-user.target
EOF

    # Habilitar serviços
    systemctl daemon-reload
    systemctl enable tor
    systemctl enable hostapd
    systemctl enable dnsmasq
    systemctl enable tor-router.service
    
    success "Inicialização automática configurada"
}

# Função principal
main() {
    header "SISTEMA ROTEADOR TOR - CORREÇÃO COMPLETA"
    
    # Verificar se é root
    if [[ $EUID -ne 0 ]]; then
        error "Este script deve ser executado como root!"
        exit 1
    fi
    
    # Detectar interfaces
    detect_wan_interface || exit 1
    detect_lan_interfaces || exit 1
    detect_wifi_interface || exit 1
    
    # Mostrar configuração detectada
    header "CONFIGURAÇÃO DETECTADA"
    info "Interface WAN: $WAN_INTERFACE"
    info "Interface WiFi: $WIFI_INTERFACE"
    info "Interfaces LAN: ${LAN_INTERFACES[*]}"
    info "Bridge LAN: $BRIDGE_NAME"
    echo
    
    read -p "Confirma a configuração? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
        warning "Operação cancelada pelo usuário"
        exit 0
    fi
    
    # Executar correções
    create_backup
    cleanup_configs
    create_lan_bridge
    configure_hostapd
    configure_dnsmasq
    configure_iptables
    save_config
    create_corrected_scripts
    configure_autostart
    
    header "CORREÇÃO COMPLETA FINALIZADA"
    success "Sistema Roteador TOR configurado com sucesso!"
    echo
    info "Comandos disponíveis:"
    info "  sudo /opt/tor_router/start_tor_router.sh   - Iniciar roteador"
    info "  sudo /opt/tor_router/stop_tor_router.sh    - Parar roteador"
    info "  sudo /opt/tor_router/status_tor_router.sh  - Ver status"
    echo
    info "Configuração salva em: $CONFIG_FILE"
    info "Backup criado em: $BACKUP_DIR"
    echo
    warning "REINICIE O SISTEMA para ativar todas as configurações:"
    warning "sudo reboot"
}

# Executar função principal
main "$@"

