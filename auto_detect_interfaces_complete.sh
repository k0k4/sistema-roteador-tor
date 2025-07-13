#!/bin/bash

# ============================================================================
# DETECÇÃO AUTOMÁTICA COMPLETA DE INTERFACES - ROTEADOR TOR K0K4
# ============================================================================
# Detecta automaticamente todas as interfaces de rede do sistema
# Identifica 1 WAN (internet) + 3 LAN (clientes TOR) + 1 WiFi (hotspot)
# Funciona mesmo sem cabos conectados
# ============================================================================

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Arquivos de configuração
CONFIG_FILE="/opt/tor_router_config.conf"
BACKUP_DIR="/opt/tor_router_backups"

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCESSO]${NC} $1"
}

error() {
    echo -e "${RED}[ERRO]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[AVISO]${NC} $1"
}

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Função para detectar interfaces ethernet
detect_ethernet_interfaces() {
    log "Detectando interfaces ethernet..."
    
    local ethernet_interfaces=()
    
    # Buscar todas as interfaces ethernet (en*, eth*)
    for iface in /sys/class/net/en* /sys/class/net/eth*; do
        if [[ -d "$iface" ]]; then
            local iface_name=$(basename "$iface")
            
            # Verificar se é interface ethernet real
            if [[ -f "$iface/type" ]]; then
                local type=$(cat "$iface/type")
                if [[ "$type" == "1" ]]; then  # Tipo 1 = Ethernet
                    ethernet_interfaces+=("$iface_name")
                    info "Interface ethernet encontrada: $iface_name"
                fi
            fi
        fi
    done
    
    # Ordenar interfaces para consistência
    IFS=$'\n' ethernet_interfaces=($(sort <<<"${ethernet_interfaces[*]}"))
    unset IFS
    
    echo "${ethernet_interfaces[@]}"
}

# Função para detectar interface WiFi
detect_wifi_interface() {
    log "Detectando interface WiFi..."
    
    local wifi_interface=""
    
    # Buscar interfaces WiFi (wl*, wlan*)
    for iface in /sys/class/net/wl* /sys/class/net/wlan*; do
        if [[ -d "$iface" ]]; then
            local iface_name=$(basename "$iface")
            
            # Verificar se tem capacidades WiFi
            if [[ -d "$iface/wireless" ]] || iw dev "$iface_name" info >/dev/null 2>&1; then
                wifi_interface="$iface_name"
                info "Interface WiFi encontrada: $iface_name"
                break
            fi
        fi
    done
    
    echo "$wifi_interface"
}

# Função para identificar interface WAN (com internet)
identify_wan_interface() {
    log "Identificando interface WAN (internet)..."
    
    local ethernet_interfaces=($1)
    local wan_interface=""
    
    # Verificar qual interface tem rota padrão
    local default_route_iface=$(ip route show default 2>/dev/null | head -1 | grep -o 'dev [^ ]*' | cut -d' ' -f2)
    
    if [[ -n "$default_route_iface" ]]; then
        # Verificar se a interface da rota padrão está na lista de ethernet
        for iface in "${ethernet_interfaces[@]}"; do
            if [[ "$iface" == "$default_route_iface" ]]; then
                wan_interface="$iface"
                info "Interface WAN identificada via rota padrão: $wan_interface"
                break
            fi
        done
    fi
    
    # Se não encontrou via rota padrão, tentar detectar por conectividade
    if [[ -z "$wan_interface" ]]; then
        log "Testando conectividade em interfaces ethernet..."
        
        for iface in "${ethernet_interfaces[@]}"; do
            # Verificar se interface está UP
            if ip link show "$iface" | grep -q "state UP"; then
                # Verificar se tem IP
                if ip addr show "$iface" | grep -q "inet "; then
                    # Testar conectividade básica
                    local gateway=$(ip route show dev "$iface" | grep default | head -1 | awk '{print $3}')
                    if [[ -n "$gateway" ]] && ping -c 1 -W 2 "$gateway" >/dev/null 2>&1; then
                        wan_interface="$iface"
                        info "Interface WAN identificada via teste de conectividade: $wan_interface"
                        break
                    fi
                fi
            fi
        done
    fi
    
    # Se ainda não encontrou, usar a primeira interface como padrão
    if [[ -z "$wan_interface" ]] && [[ ${#ethernet_interfaces[@]} -gt 0 ]]; then
        wan_interface="${ethernet_interfaces[0]}"
        warning "Interface WAN não detectada automaticamente, usando primeira interface: $wan_interface"
    fi
    
    echo "$wan_interface"
}

# Função para identificar interfaces LAN
identify_lan_interfaces() {
    log "Identificando interfaces LAN..."
    
    local ethernet_interfaces=($1)
    local wan_interface="$2"
    local lan_interfaces=()
    
    # Todas as interfaces ethernet exceto a WAN são LAN
    for iface in "${ethernet_interfaces[@]}"; do
        if [[ "$iface" != "$wan_interface" ]]; then
            lan_interfaces+=("$iface")
            info "Interface LAN identificada: $iface"
        fi
    done
    
    echo "${lan_interfaces[@]}"
}

# Função para verificar capacidades das interfaces
check_interface_capabilities() {
    local iface="$1"
    
    info "Verificando capacidades da interface $iface:"
    
    # Verificar se existe
    if [[ ! -d "/sys/class/net/$iface" ]]; then
        warning "  Interface não existe"
        return 1
    fi
    
    # Verificar tipo
    if [[ -f "/sys/class/net/$iface/type" ]]; then
        local type=$(cat "/sys/class/net/$iface/type")
        info "  Tipo: $type"
    fi
    
    # Verificar estado
    local state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
    info "  Estado: $state"
    
    # Verificar se tem carrier (cabo conectado)
    local carrier=$(cat "/sys/class/net/$iface/carrier" 2>/dev/null || echo "0")
    if [[ "$carrier" == "1" ]]; then
        info "  Cabo: CONECTADO"
    else
        info "  Cabo: DESCONECTADO (normal para configuração)"
    fi
    
    # Verificar endereço MAC
    if [[ -f "/sys/class/net/$iface/address" ]]; then
        local mac=$(cat "/sys/class/net/$iface/address")
        info "  MAC: $mac"
    fi
    
    return 0
}

# Função para criar configuração
create_configuration() {
    local wan_interface="$1"
    local wifi_interface="$2"
    shift 2
    local lan_interfaces=("$@")
    
    log "Criando arquivo de configuração..."
    
    # Criar diretório de backup se não existir
    mkdir -p "$BACKUP_DIR"
    
    # Backup da configuração anterior se existir
    if [[ -f "$CONFIG_FILE" ]]; then
        cp "$CONFIG_FILE" "$BACKUP_DIR/tor_router_config.conf.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Criar nova configuração
    cat > "$CONFIG_FILE" << EOF
# ============================================================================
# CONFIGURAÇÃO AUTOMÁTICA DO ROTEADOR TOR - SISTEMA K0K4
# ============================================================================
# Gerado automaticamente em: $(date)
# ============================================================================

# Interface WAN (Internet)
WAN_INTERFACE="$wan_interface"

# Interface WiFi (Hotspot TOR)
WIFI_INTERFACE="$wifi_interface"

# Interfaces LAN (Clientes TOR via cabo)
LAN_INTERFACES=($(printf '"%s" ' "${lan_interfaces[@]}"))

# Configurações de rede
BRIDGE_NAME="br-tor"
BRIDGE_IP="192.168.100.1"
BRIDGE_SUBNET="192.168.100.0/24"
DHCP_RANGE_START="192.168.100.10"
DHCP_RANGE_END="192.168.100.200"

# Configurações WiFi
WIFI_SSID="TOR-K0K4-Network"
WIFI_PASSWORD="TorSecure2024!"
WIFI_CHANNEL="6"
WIFI_COUNTRY="BR"

# Configurações TOR
TOR_SOCKS_PORT="9050"
TOR_DNS_PORT="9053"
TOR_CONTROL_PORT="9051"

# Configurações de monitoramento
MONITOR_INTERVAL="300"  # 5 minutos
HEALTH_CHECK_INTERVAL="60"  # 1 minuto
RECONNECT_INTERVAL="1800"  # 30 minutos

# Configurações de log
LOG_DIR="/var/log/tor_router"
LOG_LEVEL="INFO"

# ============================================================================
# RESUMO DA CONFIGURAÇÃO DETECTADA
# ============================================================================
# WAN (Internet): $wan_interface
# WiFi (Hotspot): $wifi_interface
# LAN (Bridge): ${lan_interfaces[*]}
# Total de interfaces LAN: ${#lan_interfaces[@]}
# ============================================================================
EOF

    success "Configuração criada: $CONFIG_FILE"
}

# Função para validar configuração
validate_configuration() {
    log "Validando configuração..."
    
    local issues=0
    
    # Carregar configuração
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error "Arquivo de configuração não encontrado"
        return 1
    fi
    
    source "$CONFIG_FILE"
    
    # Validar interface WAN
    if [[ -z "$WAN_INTERFACE" ]]; then
        error "Interface WAN não definida"
        issues=$((issues + 1))
    elif [[ ! -d "/sys/class/net/$WAN_INTERFACE" ]]; then
        error "Interface WAN não existe: $WAN_INTERFACE"
        issues=$((issues + 1))
    else
        success "Interface WAN válida: $WAN_INTERFACE"
    fi
    
    # Validar interface WiFi
    if [[ -z "$WIFI_INTERFACE" ]]; then
        warning "Interface WiFi não definida (hotspot não funcionará)"
    elif [[ ! -d "/sys/class/net/$WIFI_INTERFACE" ]]; then
        error "Interface WiFi não existe: $WIFI_INTERFACE"
        issues=$((issues + 1))
    else
        success "Interface WiFi válida: $WIFI_INTERFACE"
    fi
    
    # Validar interfaces LAN
    if [[ ${#LAN_INTERFACES[@]} -eq 0 ]]; then
        warning "Nenhuma interface LAN definida (apenas WiFi funcionará)"
    else
        success "Interfaces LAN encontradas: ${#LAN_INTERFACES[@]}"
        
        for iface in "${LAN_INTERFACES[@]}"; do
            if [[ ! -d "/sys/class/net/$iface" ]]; then
                error "Interface LAN não existe: $iface"
                issues=$((issues + 1))
            else
                info "Interface LAN válida: $iface"
            fi
        done
    fi
    
    # Verificar conflitos
    local all_interfaces=("$WAN_INTERFACE" "$WIFI_INTERFACE" "${LAN_INTERFACES[@]}")
    local unique_interfaces=($(printf '%s\n' "${all_interfaces[@]}" | sort -u))
    
    if [[ ${#all_interfaces[@]} -ne ${#unique_interfaces[@]} ]]; then
        error "Interfaces duplicadas detectadas"
        issues=$((issues + 1))
    fi
    
    if [[ $issues -eq 0 ]]; then
        success "Configuração validada com sucesso!"
        return 0
    else
        error "Configuração contém $issues problemas"
        return 1
    fi
}

# Função para mostrar resumo
show_summary() {
    log "Resumo da detecção automática:"
    
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        
        echo
        echo -e "${CYAN}============================================================================${NC}"
        echo -e "${CYAN}                    CONFIGURAÇÃO DETECTADA${NC}"
        echo -e "${CYAN}============================================================================${NC}"
        echo
        echo -e "${GREEN}Interface WAN (Internet):${NC}"
        echo -e "  • $WAN_INTERFACE"
        check_interface_capabilities "$WAN_INTERFACE"
        echo
        
        if [[ -n "$WIFI_INTERFACE" ]]; then
            echo -e "${GREEN}Interface WiFi (Hotspot TOR):${NC}"
            echo -e "  • $WIFI_INTERFACE"
            check_interface_capabilities "$WIFI_INTERFACE"
            echo
        fi
        
        if [[ ${#LAN_INTERFACES[@]} -gt 0 ]]; then
            echo -e "${GREEN}Interfaces LAN (Clientes TOR):${NC}"
            for iface in "${LAN_INTERFACES[@]}"; do
                echo -e "  • $iface"
                check_interface_capabilities "$iface"
            done
            echo
        fi
        
        echo -e "${GREEN}Configurações de Rede:${NC}"
        echo -e "  • Bridge: $BRIDGE_NAME ($BRIDGE_IP)"
        echo -e "  • DHCP: $DHCP_RANGE_START - $DHCP_RANGE_END"
        echo -e "  • WiFi SSID: $WIFI_SSID"
        echo -e "  • WiFi Senha: $WIFI_PASSWORD"
        echo
        
        echo -e "${CYAN}============================================================================${NC}"
    fi
}

# Função principal
main() {
    echo
    echo -e "${CYAN}============================================================================${NC}"
    echo -e "${CYAN}           DETECÇÃO AUTOMÁTICA DE INTERFACES - ROTEADOR TOR K0K4${NC}"
    echo -e "${CYAN}============================================================================${NC}"
    echo
    
    # Verificar se é root
    if [[ $EUID -ne 0 ]]; then
        error "Este script deve ser executado como root!"
        exit 1
    fi
    
    # Criar diretórios necessários
    mkdir -p /opt/tor_router
    mkdir -p "$BACKUP_DIR"
    
    # Detectar interfaces
    log "Iniciando detecção automática de interfaces..."
    echo
    
    # Detectar interfaces ethernet
    local ethernet_interfaces=($(detect_ethernet_interfaces))
    
    if [[ ${#ethernet_interfaces[@]} -eq 0 ]]; then
        error "Nenhuma interface ethernet encontrada!"
        exit 1
    fi
    
    success "Encontradas ${#ethernet_interfaces[@]} interfaces ethernet: ${ethernet_interfaces[*]}"
    echo
    
    # Detectar interface WiFi
    local wifi_interface=$(detect_wifi_interface)
    
    if [[ -n "$wifi_interface" ]]; then
        success "Interface WiFi encontrada: $wifi_interface"
    else
        warning "Nenhuma interface WiFi encontrada (hotspot não funcionará)"
    fi
    echo
    
    # Identificar WAN
    local wan_interface=$(identify_wan_interface "${ethernet_interfaces[*]}")
    
    if [[ -z "$wan_interface" ]]; then
        error "Não foi possível identificar interface WAN!"
        exit 1
    fi
    
    success "Interface WAN identificada: $wan_interface"
    echo
    
    # Identificar LAN
    local lan_interfaces=($(identify_lan_interfaces "${ethernet_interfaces[*]}" "$wan_interface"))
    
    if [[ ${#lan_interfaces[@]} -gt 0 ]]; then
        success "Interfaces LAN identificadas: ${lan_interfaces[*]}"
    else
        warning "Nenhuma interface LAN identificada (apenas WiFi funcionará)"
    fi
    echo
    
    # Criar configuração
    create_configuration "$wan_interface" "$wifi_interface" "${lan_interfaces[@]}"
    echo
    
    # Validar configuração
    if validate_configuration; then
        echo
        show_summary
        echo
        success "DETECÇÃO AUTOMÁTICA CONCLUÍDA COM SUCESSO!"
        echo
        info "Próximos passos:"
        info "  1. Executar: sudo ./tor_router_complete_fix.sh"
        info "  2. Reiniciar: sudo reboot"
        info "  3. Verificar: sudo /opt/tor_router/status_tor_router.sh"
    else
        echo
        error "DETECÇÃO AUTOMÁTICA CONCLUÍDA COM PROBLEMAS"
        echo
        warning "Verifique a configuração em: $CONFIG_FILE"
        warning "Execute novamente ou corrija manualmente"
        exit 1
    fi
}

# Executar função principal
main "$@"

