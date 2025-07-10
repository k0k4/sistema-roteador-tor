#!/bin/bash

# ============================================================================
# DETECÇÃO AUTOMÁTICA DE INTERFACES
# ============================================================================
# Detecta automaticamente as interfaces de rede e configura os scripts
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

header "DETECÇÃO AUTOMÁTICA DE INTERFACES"

# Função para detectar interface de internet ativa
detect_internet_interface() {
    local internet_iface=""
    
    # Procurar por interface com rota padrão
    internet_iface=$(ip route show default | head -1 | awk '{print $5}' 2>/dev/null || true)
    
    if [[ -n "$internet_iface" && "$internet_iface" != "lo" ]]; then
        echo "$internet_iface"
        return 0
    fi
    
    # Fallback: procurar por interface ethernet com IP
    for iface in $(ls /sys/class/net/ | grep -E '^(eth|enp|ens|eno)'); do
        if [[ -d "/sys/class/net/$iface" ]] && [[ "$iface" != "lo" ]]; then
            if ip addr show "$iface" | grep -q "inet.*scope global"; then
                echo "$iface"
                return 0
            fi
        fi
    done
    
    return 1
}

# Função para detectar interface WiFi
detect_wifi_interface() {
    local wifi_iface=""
    
    # Procurar por interfaces WiFi
    for iface in $(ls /sys/class/net/ | grep -E '^(wlan|wlp|wlx)'); do
        if [[ -d "/sys/class/net/$iface" ]]; then
            # Verificar se é interface WiFi
            if [[ -d "/sys/class/net/$iface/wireless" ]] || iw dev "$iface" info >/dev/null 2>&1; then
                echo "$iface"
                return 0
            fi
        fi
    done
    
    return 1
}

# Função para detectar interface LAN adicional
detect_lan_interface() {
    local lan_iface=""
    local internet_iface="$1"
    
    # Procurar por interface ethernet diferente da de internet
    for iface in $(ls /sys/class/net/ | grep -E '^(eth|enp|ens|eno)'); do
        if [[ -d "/sys/class/net/$iface" ]] && [[ "$iface" != "lo" ]] && [[ "$iface" != "$internet_iface" ]]; then
            echo "$iface"
            return 0
        fi
    done
    
    return 1
}

log "Iniciando detecção de interfaces..."

# Detectar interfaces
log "Detectando interface de internet..."
INTERNET_INTERFACE=$(detect_internet_interface)
if [[ -z "$INTERNET_INTERFACE" ]]; then
    error "Interface de internet não detectada!"
    echo "Interfaces disponíveis:"
    ls /sys/class/net/ | grep -v lo
    exit 1
fi

log "Detectando interface WiFi..."
WIFI_INTERFACE=$(detect_wifi_interface)
if [[ -z "$WIFI_INTERFACE" ]]; then
    error "Interface WiFi não detectada!"
    echo "Interfaces disponíveis:"
    ls /sys/class/net/
    exit 1
fi

log "Detectando interface LAN adicional..."
LAN_INTERFACE=$(detect_lan_interface "$INTERNET_INTERFACE")
if [[ -z "$LAN_INTERFACE" ]]; then
    warning "Interface LAN adicional não detectada (opcional)"
    LAN_INTERFACE="none"
fi

header "INTERFACES DETECTADAS"
success "Interface de Internet: $INTERNET_INTERFACE"
success "Interface WiFi: $WIFI_INTERFACE"
if [[ "$LAN_INTERFACE" != "none" ]]; then
    success "Interface LAN: $LAN_INTERFACE"
else
    warning "Interface LAN: Não detectada"
fi

# Mostrar informações detalhadas
header "INFORMAÇÕES DETALHADAS"

echo "Interface de Internet ($INTERNET_INTERFACE):"
ip addr show "$INTERNET_INTERFACE" | grep -E "(inet|ether)" | sed 's/^/  /'
echo

echo "Interface WiFi ($WIFI_INTERFACE):"
ip addr show "$WIFI_INTERFACE" | grep -E "(inet|ether)" | sed 's/^/  /'
if iw dev "$WIFI_INTERFACE" info >/dev/null 2>&1; then
    echo "  Tipo: WiFi confirmado"
else
    echo "  Tipo: Possível WiFi (verificação falhou)"
fi
echo

if [[ "$LAN_INTERFACE" != "none" ]]; then
    echo "Interface LAN ($LAN_INTERFACE):"
    ip addr show "$LAN_INTERFACE" | grep -E "(inet|ether)" | sed 's/^/  /'
    echo
fi

# Salvar configuração detectada
CONFIG_FILE="/opt/tor_router_interfaces.conf"
log "Salvando configuração em $CONFIG_FILE..."

cat > "$CONFIG_FILE" << EOF
# Configuração de interfaces detectada automaticamente
# Gerado em: $(date)

INTERNET_INTERFACE="$INTERNET_INTERFACE"
WIFI_INTERFACE="$WIFI_INTERFACE"
LAN_INTERFACE="$LAN_INTERFACE"

# Informações do sistema
HOSTNAME="$(hostname)"
KERNEL="$(uname -r)"
DISTRO="$(lsb_release -d 2>/dev/null | cut -f2 || echo 'Unknown')"
EOF

success "Configuração salva em $CONFIG_FILE"

# Criar script de aplicação das configurações
header "CRIANDO SCRIPT DE APLICAÇÃO"

cat > /opt/apply_tor_router_config.sh << 'EOF'
#!/bin/bash

# Script para aplicar configuração de interfaces detectadas

CONFIG_FILE="/opt/tor_router_interfaces.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "ERRO: Arquivo de configuração não encontrado: $CONFIG_FILE"
    echo "Execute primeiro: auto_detect_interfaces.sh"
    exit 1
fi

# Carregar configuração
source "$CONFIG_FILE"

echo "=== APLICANDO CONFIGURAÇÃO DE INTERFACES ==="
echo "Internet: $INTERNET_INTERFACE"
echo "WiFi: $WIFI_INTERFACE"
echo "LAN: $LAN_INTERFACE"
echo

# Verificar se diretório dos scripts existe
if [[ ! -d "/opt/tor_router" ]]; then
    echo "ERRO: Diretório /opt/tor_router não encontrado!"
    exit 1
fi

# Fazer backup
BACKUP_DIR="/opt/tor_router_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r /opt/tor_router/* "$BACKUP_DIR/" 2>/dev/null || true
echo "Backup criado em: $BACKUP_DIR"

# Aplicar configuração nos scripts existentes
echo "Atualizando scripts..."

# Substituir interfaces nos scripts
for script in /opt/tor_router/*.sh; do
    if [[ -f "$script" ]]; then
        # Fazer backup individual
        cp "$script" "$script.backup"
        
        # Substituir interfaces genéricas pelas detectadas
        sed -i "s/wlan0/$WIFI_INTERFACE/g" "$script"
        sed -i "s/eth0/$INTERNET_INTERFACE/g" "$script"
        sed -i "s/eth1/$LAN_INTERFACE/g" "$script"
        sed -i "s/enp1s0/$INTERNET_INTERFACE/g" "$script"
        sed -i "s/wlxc01c30362502/$WIFI_INTERFACE/g" "$script"
        
        echo "Atualizado: $(basename "$script")"
    fi
done

# Atualizar configurações do sistema
echo "Atualizando configurações do sistema..."

# Hostapd
if [[ -f "/etc/hostapd/hostapd.conf" ]]; then
    cp /etc/hostapd/hostapd.conf /etc/hostapd/hostapd.conf.backup
    sed -i "s/interface=.*/interface=$WIFI_INTERFACE/" /etc/hostapd/hostapd.conf
    echo "Hostapd atualizado"
fi

# Dnsmasq
if [[ -f "/etc/dnsmasq.conf" ]]; then
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup
    sed -i "s/interface=.*/interface=$WIFI_INTERFACE/" /etc/dnsmasq.conf
    echo "Dnsmasq atualizado"
fi

echo
echo "Configuração aplicada com sucesso!"
echo "Teste com: sudo /opt/tor_router/start_tor_router.sh"
EOF

chmod +x /opt/apply_tor_router_config.sh

success "Script de aplicação criado: /opt/apply_tor_router_config.sh"

header "PRÓXIMOS PASSOS"
echo
echo "1. Para aplicar a configuração aos scripts existentes:"
echo "   sudo /opt/apply_tor_router_config.sh"
echo
echo "2. Para testar o roteador TOR:"
echo "   sudo /opt/tor_router/start_tor_router.sh"
echo
echo "3. Para verificar status:"
echo "   sudo /opt/tor_router/status_tor_router.sh"
echo

log "Detecção automática concluída!"
EOF

