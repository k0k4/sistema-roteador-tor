#!/bin/bash

# ============================================================================
# INSTALAÇÃO SEGURA DO ROTEADOR TOR
# ============================================================================
# Autor: Manus AI
# Data: 2025-07-09
# Versão: 2.0 (Versão Segura)
# Descrição: Instalação do roteador TOR sem quebrar conectividade
# ============================================================================

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

header() {
    echo
    echo -e "${BLUE}=== $1 ===${NC}"
    echo
}

# Verificar se é root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root (sudo)"
   exit 1
fi

header "INSTALAÇÃO SEGURA DO ROTEADOR TOR"

# Configurações padrão (podem ser personalizadas)
WIFI_SSID="k0k4-t0r-n3tw0rks"
WIFI_PASSWORD="38249"
WIFI_CHANNEL="6"
INTERNAL_NETWORK="192.168.100.0/24"
GATEWAY_IP="192.168.100.1"
DHCP_START="192.168.100.10"
DHCP_END="192.168.100.200"

# Detectar interfaces automaticamente
log "Detectando interfaces de rede..."

INTERNET_INTERFACE=""
WIFI_INTERFACE=""

# Detectar interface de internet
for iface in $(ls /sys/class/net/ | grep -E '^(eth|enp|ens)'); do
    if [[ -d "/sys/class/net/$iface" ]] && [[ "$iface" != "lo" ]]; then
        INTERNET_INTERFACE="$iface"
        break
    fi
done

# Detectar interface WiFi
for iface in $(ls /sys/class/net/ | grep -E '^(wlan|wlp|wlx)'); do
    if [[ -d "/sys/class/net/$iface" ]]; then
        WIFI_INTERFACE="$iface"
        break
    fi
done

if [[ -z "$INTERNET_INTERFACE" ]]; then
    error "Interface de internet não detectada!"
    exit 1
fi

if [[ -z "$WIFI_INTERFACE" ]]; then
    error "Interface WiFi não detectada!"
    exit 1
fi

success "Interfaces detectadas:"
log "Internet: $INTERNET_INTERFACE"
log "WiFi: $WIFI_INTERFACE"

# Criar backup das configurações atuais
header "CRIANDO BACKUP DAS CONFIGURAÇÕES"

BACKUP_DIR="/opt/network_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup das configurações de rede
cp -r /etc/NetworkManager "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/dhcp/dhclient.conf "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/systemd/resolved.conf "$BACKUP_DIR/" 2>/dev/null || true

success "Backup criado em: $BACKUP_DIR"

# Atualizar sistema
header "ATUALIZANDO SISTEMA"
log "Atualizando lista de pacotes..."
apt update -y

# Instalar pacotes necessários
header "INSTALANDO PACOTES"
log "Instalando pacotes essenciais..."

# Remover pacotes conflitantes primeiro
apt remove --purge -y iptables-persistent netfilter-persistent 2>/dev/null || true

# Instalar pacotes sem conflitos
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
    python3 \
    python3-pip \
    systemd-timesyncd \
    fail2ban

success "Pacotes instalados com sucesso"

# Configurar TOR
header "CONFIGURANDO TOR"
log "Criando configuração do TOR..."

cp /etc/tor/torrc /etc/tor/torrc.backup

cat > /etc/tor/torrc << 'EOF'
# Configuração do Roteador TOR
User debian-tor
PidFile /var/run/tor/tor.pid
Log notice file /var/log/tor/tor.log
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
ExitPolicy reject *:*
EOF

# Configurar hostapd
header "CONFIGURANDO HOSTAPD"
log "Criando configuração do hostapd..."

cat > /etc/hostapd/hostapd.conf << EOF
# Configuração do Access Point
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
EOF

# Configurar dnsmasq
header "CONFIGURANDO DNSMASQ"
log "Criando configuração do dnsmasq..."

cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup

cat > /etc/dnsmasq.conf << EOF
# Configuração do DHCP/DNS
interface=$WIFI_INTERFACE
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,24h
dhcp-option=3,$GATEWAY_IP
dhcp-option=6,$GATEWAY_IP
server=127.0.0.1#9053
log-queries
log-dhcp
conf-file=
EOF

# Configurar iptables (firewall)
header "CONFIGURANDO FIREWALL"
log "Configurando regras de firewall..."

# Criar script de firewall
cat > /opt/setup_firewall.sh << EOF
#!/bin/bash

# Limpar regras existentes
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Políticas padrão
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# NAT para internet
iptables -t nat -A POSTROUTING -o $INTERNET_INTERFACE -j MASQUERADE
iptables -A FORWARD -i $INTERNET_INTERFACE -o $WIFI_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $WIFI_INTERFACE -o $INTERNET_INTERFACE -j ACCEPT

# Redirecionar tráfego para TOR
iptables -t nat -A PREROUTING -i $WIFI_INTERFACE -p tcp --dport 22 -j REDIRECT --to-ports 22
iptables -t nat -A PREROUTING -i $WIFI_INTERFACE -p tcp --syn -j REDIRECT --to-ports 9040
iptables -t nat -A PREROUTING -i $WIFI_INTERFACE -p udp --dport 53 -j REDIRECT --to-ports 9053

# Salvar regras
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
EOF

chmod +x /opt/setup_firewall.sh

# Configurar interfaces de rede de forma SEGURA
header "CONFIGURANDO INTERFACES DE REDE (MODO SEGURO)"

log "Configurando interface WiFi para modo AP..."

# Criar configuração NetworkManager para WiFi AP
cat > "/etc/NetworkManager/system-connections/TOR-AP.nmconnection" << EOF
[connection]
id=TOR-AP
uuid=$(uuidgen)
type=wifi
interface-name=$WIFI_INTERFACE
autoconnect=false

[wifi]
mode=ap
ssid=$WIFI_SSID

[wifi-security]
key-mgmt=wpa-psk
psk=$WIFI_PASSWORD

[ipv4]
address1=$GATEWAY_IP/24
method=manual

[ipv6]
addr-gen-mode=stable-privacy
method=ignore
EOF

chmod 600 "/etc/NetworkManager/system-connections/TOR-AP.nmconnection"

# Habilitar IP forwarding
log "Habilitando IP forwarding..."
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# Criar scripts de controle
header "CRIANDO SCRIPTS DE CONTROLE"

# Script para iniciar roteador TOR
cat > /opt/start_tor_router.sh << 'EOF'
#!/bin/bash

echo "=== INICIANDO ROTEADOR TOR ==="

# Configurar firewall
/opt/setup_firewall.sh

# Ativar AP WiFi
nmcli connection up TOR-AP 2>/dev/null || true

# Iniciar serviços
systemctl start tor
systemctl start dnsmasq

# Aguardar inicialização
sleep 5

echo "Status dos serviços:"
systemctl is-active tor dnsmasq

echo "Roteador TOR iniciado!"
echo "SSID WiFi: k0k4-t0r-n3tw0rks"
echo "Senha: 38249"
echo "Gateway: 192.168.100.1"
EOF

# Script para parar roteador TOR
cat > /opt/stop_tor_router.sh << 'EOF'
#!/bin/bash

echo "=== PARANDO ROTEADOR TOR ==="

# Parar serviços
systemctl stop tor
systemctl stop dnsmasq

# Desativar AP WiFi
nmcli connection down TOR-AP 2>/dev/null || true

# Limpar firewall
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

echo "Roteador TOR parado!"
EOF

# Script de status
cat > /opt/status_tor_router.sh << 'EOF'
#!/bin/bash

echo "=== STATUS DO ROTEADOR TOR ==="
echo

echo "Serviços:"
echo "TOR: $(systemctl is-active tor)"
echo "DNSMASQ: $(systemctl is-active dnsmasq)"
echo

echo "Interface WiFi:"
nmcli connection show --active | grep TOR-AP || echo "AP não ativo"
echo

echo "Conectividade TOR:"
curl --socks5 127.0.0.1:9050 -s https://check.torproject.org/api/ip | grep -o '"IsTor":[^,]*' || echo "TOR não conectado"
EOF

# Dar permissões aos scripts
chmod +x /opt/start_tor_router.sh
chmod +x /opt/stop_tor_router.sh  
chmod +x /opt/status_tor_router.sh

# Configurar serviços (SEM desabilitar NetworkManager)
header "CONFIGURANDO SERVIÇOS"

log "Habilitando serviços necessários..."
systemctl enable tor
systemctl enable systemd-timesyncd

# NÃO desabilitar NetworkManager - manter para conectividade
log "Mantendo NetworkManager ativo para conectividade segura"

success "Instalação concluída com sucesso!"

header "INSTRUÇÕES DE USO"
echo
success "Instalação segura concluída!"
echo
echo "COMANDOS DISPONÍVEIS:"
echo "• Iniciar roteador TOR: sudo /opt/start_tor_router.sh"
echo "• Parar roteador TOR:   sudo /opt/stop_tor_router.sh"
echo "• Ver status:           sudo /opt/status_tor_router.sh"
echo
echo "CONFIGURAÇÕES:"
echo "• SSID WiFi: $WIFI_SSID"
echo "• Senha WiFi: $WIFI_PASSWORD"
echo "• Gateway: $GATEWAY_IP"
echo
warning "IMPORTANTE: Esta versão mantém o NetworkManager ativo"
warning "para preservar a conectividade de internet principal."
echo
log "Para iniciar o roteador TOR, execute:"
echo "sudo /opt/start_tor_router.sh"

