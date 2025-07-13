#!/bin/bash

# ============================================================================
# CORREÇÃO ROBUSTA DO ROTEADOR TOR - SISTEMA K0K4
# ============================================================================
# Corrige problemas específicos identificados:
# - Dnsmasq com erro na linha 35
# - Bridge sem interfaces adicionadas
# - Sistema de inicialização não robusto
# ============================================================================

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuração
CONFIG_FILE="/opt/tor_router_config.conf"
BRIDGE_NAME="br-tor"
RETRY_COUNT=3
RETRY_DELAY=5

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

# Função para carregar configuração
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        success "Configuração carregada: $CONFIG_FILE"
    else
        error "Arquivo de configuração não encontrado: $CONFIG_FILE"
        exit 1
    fi
}

# Função para parar serviços
stop_services() {
    log "Parando serviços..."
    systemctl stop dnsmasq 2>/dev/null || true
    systemctl stop hostapd 2>/dev/null || true
    systemctl stop tor 2>/dev/null || true
    sleep 2
}

# Função para corrigir configuração do dnsmasq
fix_dnsmasq_config() {
    log "Corrigindo configuração do dnsmasq..."
    
    # Backup da configuração atual
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    
    # Criar configuração limpa e correta
    cat > /etc/dnsmasq.conf << EOF
# Configuração DNSMASQ - Roteador TOR K0K4
# Configuração limpa sem conflitos

# Interfaces
interface=$WIFI_INTERFACE
interface=$BRIDGE_NAME
bind-interfaces

# DHCP
dhcp-range=192.168.100.10,192.168.100.200,255.255.255.0,12h
dhcp-option=3,192.168.100.1
dhcp-option=6,192.168.100.1

# DNS
server=127.0.0.1#9053
no-resolv
cache-size=1000

# Segurança
bogus-priv
domain-needed
dhcp-authoritative

# Log
log-queries
log-dhcp
log-facility=/var/log/dnsmasq.log
EOF

    success "Configuração do dnsmasq corrigida"
}

# Função robusta para adicionar interfaces ao bridge
add_interfaces_to_bridge() {
    log "Adicionando interfaces ao bridge de forma robusta..."
    
    # Verificar se bridge existe
    if ! ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
        warning "Bridge não existe, criando..."
        ip link add name "$BRIDGE_NAME" type bridge
        ip link set dev "$BRIDGE_NAME" up
        ip addr add 192.168.100.1/24 dev "$BRIDGE_NAME"
    fi
    
    # Adicionar cada interface LAN ao bridge com retry
    for iface in "${LAN_INTERFACES[@]}"; do
        log "Processando interface: $iface"
        
        # Verificar se interface existe
        if [[ ! -d "/sys/class/net/$iface" ]]; then
            warning "Interface $iface não existe, pulando..."
            continue
        fi
        
        # Tentar adicionar ao bridge com retry
        local retry=0
        while [[ $retry -lt $RETRY_COUNT ]]; do
            # Preparar interface
            ip link set dev "$iface" down 2>/dev/null || true
            ip addr flush dev "$iface" 2>/dev/null || true
            ip link set dev "$iface" up
            
            # Adicionar ao bridge
            if ip link set dev "$iface" master "$BRIDGE_NAME" 2>/dev/null; then
                success "Interface $iface adicionada ao bridge"
                break
            else
                retry=$((retry + 1))
                warning "Tentativa $retry falhou para $iface, tentando novamente em ${RETRY_DELAY}s..."
                sleep $RETRY_DELAY
            fi
        done
        
        if [[ $retry -eq $RETRY_COUNT ]]; then
            error "Falha ao adicionar $iface ao bridge após $RETRY_COUNT tentativas"
        fi
    done
}

# Função para verificar e corrigir WiFi
fix_wifi_interface() {
    log "Verificando e corrigindo interface WiFi..."
    
    # Verificar se interface WiFi existe
    if [[ ! -d "/sys/class/net/$WIFI_INTERFACE" ]]; then
        error "Interface WiFi $WIFI_INTERFACE não encontrada!"
        return 1
    fi
    
    # Configurar interface WiFi
    ip link set dev "$WIFI_INTERFACE" down 2>/dev/null || true
    ip addr flush dev "$WIFI_INTERFACE" 2>/dev/null || true
    ip addr add 192.168.100.1/24 dev "$WIFI_INTERFACE" 2>/dev/null || true
    ip link set dev "$WIFI_INTERFACE" up
    
    success "Interface WiFi configurada"
}

# Função para iniciar serviços com retry
start_services_robust() {
    log "Iniciando serviços de forma robusta..."
    
    # Array de serviços na ordem correta
    local services=("tor" "hostapd" "dnsmasq")
    
    for service in "${services[@]}"; do
        log "Iniciando $service..."
        
        local retry=0
        while [[ $retry -lt $RETRY_COUNT ]]; do
            if systemctl start "$service" 2>/dev/null; then
                sleep 2
                if systemctl is-active "$service" >/dev/null 2>&1; then
                    success "$service iniciado com sucesso"
                    break
                fi
            fi
            
            retry=$((retry + 1))
            warning "Tentativa $retry falhou para $service, tentando novamente em ${RETRY_DELAY}s..."
            sleep $RETRY_DELAY
        done
        
        if [[ $retry -eq $RETRY_COUNT ]]; then
            error "Falha ao iniciar $service após $RETRY_COUNT tentativas"
            # Mostrar logs para debug
            journalctl -u "$service" --no-pager -n 10
        fi
    done
}

# Função para verificar status
check_status() {
    log "Verificando status dos serviços..."
    
    local all_ok=true
    
    # Verificar serviços
    for service in tor hostapd dnsmasq; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            success "$service: ATIVO"
        else
            error "$service: INATIVO"
            all_ok=false
        fi
    done
    
    # Verificar bridge
    if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
        success "Bridge $BRIDGE_NAME: ATIVO"
        
        # Verificar interfaces no bridge
        local bridge_ok=true
        for iface in "${LAN_INTERFACES[@]}"; do
            if [[ -f "/sys/class/net/$iface/master" ]]; then
                local master=$(cat "/sys/class/net/$iface/master" 2>/dev/null | xargs basename 2>/dev/null || echo "")
                if [[ "$master" == "$BRIDGE_NAME" ]]; then
                    success "Interface $iface: NO BRIDGE"
                else
                    warning "Interface $iface: FORA DO BRIDGE"
                    bridge_ok=false
                fi
            else
                warning "Interface $iface: SEM MASTER"
                bridge_ok=false
            fi
        done
        
        if [[ "$bridge_ok" == "false" ]]; then
            all_ok=false
        fi
    else
        error "Bridge $BRIDGE_NAME: INATIVO"
        all_ok=false
    fi
    
    # Verificar conectividade TOR
    if curl -s --socks5 127.0.0.1:9050 --connect-timeout 10 https://check.torproject.org/api/ip >/dev/null 2>&1; then
        success "TOR: CONECTADO"
    else
        warning "TOR: NÃO CONECTADO (pode levar alguns minutos)"
    fi
    
    if [[ "$all_ok" == "true" ]]; then
        success "TODOS OS SERVIÇOS FUNCIONANDO CORRETAMENTE!"
        return 0
    else
        error "ALGUNS SERVIÇOS COM PROBLEMAS"
        return 1
    fi
}

# Função principal
main() {
    echo
    echo -e "${CYAN}============================================================================${NC}"
    echo -e "${CYAN}           CORREÇÃO ROBUSTA DO ROTEADOR TOR - SISTEMA K0K4${NC}"
    echo -e "${CYAN}============================================================================${NC}"
    echo
    
    # Verificar se é root
    if [[ $EUID -ne 0 ]]; then
        error "Este script deve ser executado como root!"
        exit 1
    fi
    
    # Carregar configuração
    load_config
    
    info "Configuração carregada:"
    info "  WAN: $WAN_INTERFACE"
    info "  WiFi: $WIFI_INTERFACE"
    info "  Bridge: $BRIDGE_NAME"
    info "  LAN: ${LAN_INTERFACES[*]}"
    echo
    
    # Executar correções
    stop_services
    fix_dnsmasq_config
    add_interfaces_to_bridge
    fix_wifi_interface
    start_services_robust
    
    echo
    echo -e "${CYAN}============================================================================${NC}"
    echo -e "${CYAN}                           VERIFICAÇÃO FINAL${NC}"
    echo -e "${CYAN}============================================================================${NC}"
    echo
    
    # Verificar status final
    if check_status; then
        echo
        success "CORREÇÃO CONCLUÍDA COM SUCESSO!"
        echo
        info "Rede WiFi disponível:"
        info "  SSID: TOR-K0K4-Network"
        info "  Senha: TorSecure2024!"
        info "  Gateway: 192.168.100.1"
        echo
        info "Para verificar status: sudo /opt/tor_router/status_tor_router.sh"
    else
        echo
        error "CORREÇÃO CONCLUÍDA COM ALGUNS PROBLEMAS"
        echo
        warning "Execute novamente ou verifique os logs:"
        warning "  sudo journalctl -u dnsmasq -n 20"
        warning "  sudo journalctl -u hostapd -n 20"
    fi
}

# Executar função principal
main "$@"

