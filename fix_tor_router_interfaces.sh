#!/bin/bash

# ============================================================================
# CORREÇÃO DE INTERFACES - SCRIPTS EXISTENTES
# ============================================================================
# Corrige os scripts em /opt/tor_router/ para usar as interfaces corretas
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

success() {
    echo -e "${GREEN}[SUCESSO]${NC} $1"
}

header() {
    echo
    echo -e "${BLUE}=== $1 ===${NC}"
    echo
}

# Verificar se é root
if [[ $EUID -ne 0 ]]; then
   echo "Este script deve ser executado como root (sudo)"
   exit 1
fi

# Interfaces específicas do sistema K0K4
INTERNET_INTERFACE="enp1s0"
WIFI_INTERFACE="wlxc01c30362502"
LAN_INTERFACE="enp2s0"

header "CORREÇÃO DE INTERFACES - SCRIPTS TOR ROUTER"

log "Interfaces corretas:"
log "Internet: $INTERNET_INTERFACE"
log "WiFi: $WIFI_INTERFACE"
log "LAN: $LAN_INTERFACE"

# Verificar se diretório existe
if [[ ! -d "/opt/tor_router" ]]; then
    echo "Diretório /opt/tor_router não encontrado!"
    exit 1
fi

# Fazer backup dos scripts originais
BACKUP_DIR="/opt/tor_router_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r /opt/tor_router/* "$BACKUP_DIR/" 2>/dev/null || true

log "Backup criado em: $BACKUP_DIR"

# Corrigir start_tor_router.sh
header "CORRIGINDO start_tor_router.sh"

cat > /opt/tor_router/start_tor_router.sh << EOF
#!/bin/bash

# Script corrigido para iniciar roteador TOR com interfaces específicas

echo "Iniciando Roteador TOR..."

# Interfaces específicas do sistema K0K4
INTERNET_INTERFACE="$INTERNET_INTERFACE"
WIFI_INTERFACE="$WIFI_INTERFACE"
LAN_INTERFACE="$LAN_INTERFACE"

echo "Usando interfaces:"
echo "Internet: \$INTERNET_INTERFACE"
echo "WiFi: \$WIFI_INTERFACE"
echo "LAN: \$LAN_INTERFACE"

# Verificar se interfaces existem
if [[ ! -d "/sys/class/net/\$INTERNET_INTERFACE" ]]; then
    echo "ERRO: Interface de internet \$INTERNET_INTERFACE não encontrada!"
    exit 1
fi

if [[ ! -d "/sys/class/net/\$WIFI_INTERFACE" ]]; then
    echo "ERRO: Interface WiFi \$WIFI_INTERFACE não encontrada!"
    echo "Interfaces disponíveis:"
    ls /sys/class/net/ | grep -v lo
    exit 1
fi

# Parar NetworkManager na interface WiFi
nmcli device set "\$WIFI_INTERFACE" managed no 2>/dev/null || true

# Configurar hostapd com interface correta
cat > /etc/hostapd/hostapd.conf << EOL
interface=\$WIFI_INTERFACE
driver=nl80211
ssid=k0k4-t0r-n3tw0rks
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=38249
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOL

# Configurar dnsmasq com interface correta
cat > /etc/dnsmasq.conf << EOL
interface=\$WIFI_INTERFACE
dhcp-range=192.168.100.10,192.168.100.200,255.255.255.0,24h
dhcp-option=3,192.168.100.1
dhcp-option=6,192.168.100.1
server=127.0.0.1#9053
log-queries
log-dhcp
conf-file=
EOL

# Configurar interface WiFi para AP
ip addr flush dev "\$WIFI_INTERFACE" 2>/dev/null || true
ip addr add 192.168.100.1/24 dev "\$WIFI_INTERFACE"
ip link set "\$WIFI_INTERFACE" up

# Configurar iptables
echo "Configurando firewall..."
/opt/tor_router/setup_iptables.sh

# Iniciar serviços
echo "Iniciando serviços..."
systemctl start tor
systemctl start hostapd
systemctl start dnsmasq

# Aguardar inicialização
sleep 3

echo "Roteador TOR iniciado com sucesso!"
echo "SSID: k0k4-t0r-n3tw0rks"
echo "Senha: 38249"
echo "Gateway: 192.168.100.1"
EOF

chmod +x /opt/tor_router/start_tor_router.sh

# Corrigir setup_iptables.sh
header "CORRIGINDO setup_iptables.sh"

cat > /opt/tor_router/setup_iptables.sh << EOF
#!/bin/bash

# Script corrigido para configurar iptables com interfaces específicas

# Interfaces específicas do sistema K0K4
INTERNET_INTERFACE="$INTERNET_INTERFACE"
WIFI_INTERFACE="$WIFI_INTERFACE"

echo "Configurando iptables..."
echo "Internet: \$INTERNET_INTERFACE"
echo "WiFi: \$WIFI_INTERFACE"

# Limpar regras existentes
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Políticas padrão
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Habilitar IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# NAT para internet
iptables -t nat -A POSTROUTING -o "\$INTERNET_INTERFACE" -j MASQUERADE
iptables -A FORWARD -i "\$INTERNET_INTERFACE" -o "\$WIFI_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i "\$WIFI_INTERFACE" -o "\$INTERNET_INTERFACE" -j ACCEPT

# Redirecionar tráfego para TOR
iptables -t nat -A PREROUTING -i "\$WIFI_INTERFACE" -p tcp --dport 22 -j REDIRECT --to-ports 22
iptables -t nat -A PREROUTING -i "\$WIFI_INTERFACE" -p tcp --syn -j REDIRECT --to-ports 9040
iptables -t nat -A PREROUTING -i "\$WIFI_INTERFACE" -p udp --dport 53 -j REDIRECT --to-ports 9053

# Permitir loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

echo "Firewall configurado com sucesso!"
EOF

chmod +x /opt/tor_router/setup_iptables.sh

# Corrigir stop_tor_router.sh
header "CORRIGINDO stop_tor_router.sh"

cat > /opt/tor_router/stop_tor_router.sh << EOF
#!/bin/bash

# Script corrigido para parar roteador TOR

echo "Parando Roteador TOR..."

# Interfaces específicas do sistema K0K4
WIFI_INTERFACE="$WIFI_INTERFACE"

# Parar serviços
systemctl stop hostapd 2>/dev/null || true
systemctl stop dnsmasq 2>/dev/null || true
systemctl stop tor 2>/dev/null || true

# Limpar configuração da interface WiFi
ip addr flush dev "\$WIFI_INTERFACE" 2>/dev/null || true

# Reativar gerenciamento pelo NetworkManager
nmcli device set "\$WIFI_INTERFACE" managed yes 2>/dev/null || true

# Limpar firewall
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

echo "Roteador TOR parado!"
EOF

chmod +x /opt/tor_router/stop_tor_router.sh

# Corrigir status_tor_router.sh
header "CORRIGINDO status_tor_router.sh"

cat > /opt/tor_router/status_tor_router.sh << EOF
#!/bin/bash

# Script corrigido para verificar status do roteador TOR

echo "=== STATUS DO ROTEADOR TOR - SISTEMA K0K4 ==="
echo

# Interfaces específicas
INTERNET_INTERFACE="$INTERNET_INTERFACE"
WIFI_INTERFACE="$WIFI_INTERFACE"

echo "INTERFACES:"
echo "Internet: \$INTERNET_INTERFACE"
echo "WiFi: \$WIFI_INTERFACE"
echo

echo "STATUS DOS SERVIÇOS:"
echo "TOR: \$(systemctl is-active tor 2>/dev/null || echo 'inativo')"
echo "HOSTAPD: \$(systemctl is-active hostapd 2>/dev/null || echo 'inativo')"
echo "DNSMASQ: \$(systemctl is-active dnsmasq 2>/dev/null || echo 'inativo')"
echo

echo "INTERFACE DE INTERNET (\$INTERNET_INTERFACE):"
ip addr show "\$INTERNET_INTERFACE" | grep inet || echo "Sem IP configurado"
echo

echo "INTERFACE WIFI (\$WIFI_INTERFACE):"
if [[ -d "/sys/class/net/\$WIFI_INTERFACE" ]]; then
    ip addr show "\$WIFI_INTERFACE" | grep inet || echo "Sem IP configurado"
    echo "Status: \$(cat /sys/class/net/\$WIFI_INTERFACE/operstate 2>/dev/null || echo 'desconhecido')"
else
    echo "Interface não encontrada!"
fi
echo

echo "CONECTIVIDADE TOR:"
if systemctl is-active tor >/dev/null 2>&1; then
    curl --socks5 127.0.0.1:9050 -s --max-time 10 https://check.torproject.org/api/ip 2>/dev/null | grep -o '"IsTor":[^,]*' || echo "TOR não conectado"
else
    echo "Serviço TOR não está rodando"
fi
echo

echo "DISPOSITIVOS CONECTADOS:"
arp -a | grep 192.168.100 | wc -l | xargs echo "Dispositivos na rede TOR:"
EOF

chmod +x /opt/tor_router/status_tor_router.sh

success "Todos os scripts foram corrigidos!"

header "SCRIPTS CORRIGIDOS"
echo "Os seguintes scripts foram atualizados com as interfaces corretas:"
echo "• /opt/tor_router/start_tor_router.sh"
echo "• /opt/tor_router/stop_tor_router.sh"
echo "• /opt/tor_router/setup_iptables.sh"
echo "• /opt/tor_router/status_tor_router.sh"
echo
echo "Backup dos originais em: $BACKUP_DIR"
echo
echo "TESTE AGORA:"
echo "sudo /opt/tor_router/start_tor_router.sh"

log "Correção de interfaces concluída!"
EOF

