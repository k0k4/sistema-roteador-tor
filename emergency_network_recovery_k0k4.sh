#!/bin/bash

# ============================================================================
# SCRIPT DE RECUPERAÇÃO DE EMERGÊNCIA - ESPECÍFICO PARA K0K4
# ============================================================================
# Interfaces específicas detectadas:
# - Internet: enp1s0
# - WiFi: wlxc01c30362502
# - LAN: enp2s0
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

# Interfaces específicas do sistema K0K4
INTERNET_INTERFACE="enp1s0"
WIFI_INTERFACE="wlxc01c30362502"
LAN_INTERFACE="enp2s0"

header "RECUPERAÇÃO DE EMERGÊNCIA - SISTEMA K0K4"
log "Interfaces detectadas:"
log "Internet: $INTERNET_INTERFACE"
log "WiFi: $WIFI_INTERFACE"
log "LAN: $LAN_INTERFACE"

# Parar todos os serviços de rede problemáticos
header "PARANDO SERVIÇOS PROBLEMÁTICOS"
log "Parando serviços que podem estar causando conflitos..."

systemctl stop tor 2>/dev/null || true
systemctl stop hostapd 2>/dev/null || true
systemctl stop dnsmasq 2>/dev/null || true
systemctl stop systemd-networkd 2>/dev/null || true
systemctl stop systemd-resolved 2>/dev/null || true

# Reativar NetworkManager
header "REATIVANDO NETWORKMANAGER"
log "Reabilitando NetworkManager para conectividade básica..."

systemctl unmask NetworkManager 2>/dev/null || true
systemctl enable NetworkManager
systemctl start NetworkManager

# Aguardar NetworkManager inicializar
sleep 5

# Limpar configurações de rede problemáticas
header "LIMPANDO CONFIGURAÇÕES PROBLEMÁTICAS"

log "Removendo configurações de rede que podem estar causando conflitos..."

# Remover configurações systemd-networkd
rm -f /etc/systemd/network/*.network 2>/dev/null || true
rm -f /etc/systemd/network/*.netdev 2>/dev/null || true

# Remover configurações hostapd problemáticas
mv /etc/hostapd/hostapd.conf /etc/hostapd/hostapd.conf.backup 2>/dev/null || true

# Restaurar configuração padrão do resolved
log "Restaurando configuração padrão do systemd-resolved..."
cat > /etc/systemd/resolved.conf << 'EOF'
[Resolve]
DNS=8.8.8.8 1.1.1.1
FallbackDNS=8.8.4.4 1.0.0.1
EOF

systemctl restart systemd-resolved

# Configurar interface de internet específica
header "CONFIGURANDO INTERFACE DE INTERNET"
log "Configurando $INTERNET_INTERFACE para DHCP..."

# Ativar interface
ip link set "$INTERNET_INTERFACE" up

# Limpar configurações antigas
nmcli connection delete "$INTERNET_INTERFACE" 2>/dev/null || true
nmcli connection delete "Wired connection 1" 2>/dev/null || true

# Configurar DHCP via NetworkManager
nmcli connection add type ethernet ifname "$INTERNET_INTERFACE" con-name "Internet-K0K4"
nmcli connection modify "Internet-K0K4" ipv4.method auto
nmcli connection modify "Internet-K0K4" ipv6.method auto
nmcli connection up "Internet-K0K4"

success "Interface $INTERNET_INTERFACE configurada"

# Configurar interface WiFi para modo managed
header "CONFIGURANDO INTERFACE WIFI"
log "Configurando $WIFI_INTERFACE para modo managed..."

# Verificar se interface WiFi existe
if [[ -d "/sys/class/net/$WIFI_INTERFACE" ]]; then
    # Ativar interface WiFi
    ip link set "$WIFI_INTERFACE" up
    
    # Configurar para modo managed
    iw dev "$WIFI_INTERFACE" set type managed 2>/dev/null || true
    
    # Permitir que NetworkManager gerencie
    nmcli device set "$WIFI_INTERFACE" managed yes
    
    success "Interface WiFi $WIFI_INTERFACE configurada"
else
    warning "Interface WiFi $WIFI_INTERFACE não encontrada"
    log "Tentando detectar interface WiFi USB..."
    
    # Procurar por interfaces WiFi USB
    for iface in $(ls /sys/class/net/ | grep -E '^(wlx|wlan)'); do
        if [[ -d "/sys/class/net/$iface" ]]; then
            WIFI_INTERFACE="$iface"
            log "Interface WiFi alternativa encontrada: $WIFI_INTERFACE"
            ip link set "$WIFI_INTERFACE" up
            iw dev "$WIFI_INTERFACE" set type managed 2>/dev/null || true
            nmcli device set "$WIFI_INTERFACE" managed yes
            break
        fi
    done
fi

# Aguardar conectividade
header "TESTANDO CONECTIVIDADE"
log "Aguardando conectividade de rede..."

for i in {1..30}; do
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        success "Conectividade restaurada!"
        break
    fi
    echo -n "."
    sleep 2
done

echo

# Verificar conectividade final
if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    success "Internet funcionando!"
    
    # Mostrar informações de rede
    header "INFORMAÇÕES DE REDE ATUAIS"
    echo "Interface de internet ($INTERNET_INTERFACE):"
    ip addr show "$INTERNET_INTERFACE" | grep inet
    
    echo
    echo "Rota padrão:"
    ip route show default
    
    echo
    echo "DNS configurado:"
    cat /etc/resolv.conf | grep nameserver
    
else
    error "Ainda sem conectividade. Tentativas adicionais necessárias."
    log "Tentando configuração manual..."
    
    # Tentar DHCP manual
    dhclient -r "$INTERNET_INTERFACE" 2>/dev/null || true
    dhclient "$INTERNET_INTERFACE" 2>/dev/null || true
fi

# Criar script de restauração do roteador TOR específico
header "CRIANDO SCRIPT DE RESTAURAÇÃO DO ROTEADOR TOR"

cat > /opt/restore_tor_router_k0k4.sh << EOF
#!/bin/bash

# Script para restaurar roteador TOR com interfaces específicas K0K4

echo "=== RESTAURANDO ROTEADOR TOR - SISTEMA K0K4 ==="

# Interfaces específicas
INTERNET_INTERFACE="$INTERNET_INTERFACE"
WIFI_INTERFACE="$WIFI_INTERFACE"
LAN_INTERFACE="$LAN_INTERFACE"

# Verificar se há internet
if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    echo "ERRO: Sem conectividade de internet. Execute primeiro emergency_network_recovery_k0k4.sh"
    exit 1
fi

echo "Configurando interfaces para modo roteador..."
echo "Internet: \$INTERNET_INTERFACE"
echo "WiFi: \$WIFI_INTERFACE"
echo "LAN: \$LAN_INTERFACE"

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

# Configurar iptables com interfaces corretas
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# NAT para internet
iptables -t nat -A POSTROUTING -o "\$INTERNET_INTERFACE" -j MASQUERADE
iptables -A FORWARD -i "\$INTERNET_INTERFACE" -o "\$WIFI_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i "\$WIFI_INTERFACE" -o "\$INTERNET_INTERFACE" -j ACCEPT

# Redirecionar tráfego para TOR
iptables -t nat -A PREROUTING -i "\$WIFI_INTERFACE" -p tcp --dport 22 -j REDIRECT --to-ports 22
iptables -t nat -A PREROUTING -i "\$WIFI_INTERFACE" -p tcp --syn -j REDIRECT --to-ports 9040
iptables -t nat -A PREROUTING -i "\$WIFI_INTERFACE" -p udp --dport 53 -j REDIRECT --to-ports 9053

# Configurar interface WiFi para AP
ip addr add 192.168.100.1/24 dev "\$WIFI_INTERFACE"
ip link set "\$WIFI_INTERFACE" up

# Iniciar serviços do roteador TOR
echo "Iniciando serviços do roteador TOR..."
systemctl start tor
systemctl start hostapd  
systemctl start dnsmasq

# Verificar status
echo "Status dos serviços:"
systemctl is-active tor hostapd dnsmasq

echo "Roteador TOR restaurado!"
echo "SSID: k0k4-t0r-n3tw0rks"
echo "Senha: 38249"
echo "Gateway: 192.168.100.1"
EOF

chmod +x /opt/restore_tor_router_k0k4.sh

success "Script de restauração específico criado em /opt/restore_tor_router_k0k4.sh"

header "RECUPERAÇÃO CONCLUÍDA"

echo
success "Rede básica restaurada para sistema K0K4!"
echo
echo "PRÓXIMOS PASSOS:"
echo "1. Verifique se a internet está funcionando: ping google.com"
echo "2. Para reativar o roteador TOR: sudo /opt/restore_tor_router_k0k4.sh"
echo
echo "INTERFACES CONFIGURADAS:"
echo "• Internet: $INTERNET_INTERFACE"
echo "• WiFi: $WIFI_INTERFACE"  
echo "• LAN: $LAN_INTERFACE"
echo

log "Recuperação de emergência específica para K0K4 concluída!"
EOF

