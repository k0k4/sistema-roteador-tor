#!/bin/bash

# ============================================================================
# SISTEMA ROBUSTO DE INICIALIZAÇÃO AUTOMÁTICA - ROTEADOR TOR K0K4
# ============================================================================
# Cria sistema de inicialização que funciona 100% no boot
# Com retry automático, verificações de saúde e auto-correção
# ============================================================================

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCESSO]${NC} $1"
}

error() {
    echo -e "${RED}[ERRO]${NC} $1"
}

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Função para criar serviço systemd robusto
create_robust_systemd_service() {
    log "Criando serviço systemd robusto..."
    
    cat > /etc/systemd/system/tor-router-robust.service << 'EOF'
[Unit]
Description=TOR Router Robust Service - Sistema K0K4
After=network.target systemd-networkd.service NetworkManager.service
Wants=network.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/opt/tor_router/start_tor_router_robust.sh
ExecStop=/opt/tor_router/stop_tor_router.sh
RemainAfterExit=yes
User=root
Restart=on-failure
RestartSec=30
TimeoutStartSec=300
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
EOF

    success "Serviço systemd robusto criado"
}

# Função para criar script de inicialização robusto
create_robust_start_script() {
    log "Criando script de inicialização robusto..."
    
    cat > /opt/tor_router/start_tor_router_robust.sh << 'EOF'
#!/bin/bash

# Script de inicialização robusto do Roteador TOR
# Com retry automático e verificações de saúde

# Configurações
MAX_RETRIES=5
RETRY_DELAY=10
HEALTH_CHECK_DELAY=30
LOG_FILE="/var/log/tor_router_robust.log"

# Função de log
log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Função para aguardar rede
wait_for_network() {
    log_msg "Aguardando conectividade de rede..."
    
    local retry=0
    while [[ $retry -lt 30 ]]; do
        if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
            log_msg "Conectividade de rede confirmada"
            return 0
        fi
        
        retry=$((retry + 1))
        log_msg "Aguardando rede... tentativa $retry/30"
        sleep 2
    done
    
    log_msg "AVISO: Prosseguindo sem confirmação de conectividade"
    return 0
}

# Função para carregar configuração
load_config() {
    if [[ -f "/opt/tor_router_config.conf" ]]; then
        source "/opt/tor_router_config.conf"
        log_msg "Configuração carregada"
        return 0
    else
        log_msg "ERRO: Configuração não encontrada"
        return 1
    fi
}

# Função para criar bridge robusto
create_bridge_robust() {
    log_msg "Criando bridge de forma robusta..."
    
    # Remover bridge existente se houver problemas
    ip link delete "$BRIDGE_NAME" 2>/dev/null || true
    
    # Criar bridge
    ip link add name "$BRIDGE_NAME" type bridge
    ip link set dev "$BRIDGE_NAME" up
    ip addr add 192.168.100.1/24 dev "$BRIDGE_NAME"
    
    # Aguardar estabilização
    sleep 3
    
    # Adicionar interfaces LAN
    for iface in "${LAN_INTERFACES[@]}"; do
        if [[ -d "/sys/class/net/$iface" ]]; then
            log_msg "Adicionando $iface ao bridge..."
            ip link set dev "$iface" down 2>/dev/null || true
            ip addr flush dev "$iface" 2>/dev/null || true
            ip link set dev "$iface" up
            ip link set dev "$iface" master "$BRIDGE_NAME" 2>/dev/null || true
            sleep 1
        fi
    done
    
    log_msg "Bridge criado com sucesso"
}

# Função para configurar WiFi robusto
configure_wifi_robust() {
    log_msg "Configurando WiFi de forma robusta..."
    
    if [[ -d "/sys/class/net/$WIFI_INTERFACE" ]]; then
        # Parar NetworkManager na interface WiFi
        nmcli device set "$WIFI_INTERFACE" managed no 2>/dev/null || true
        
        # Configurar interface
        ip link set dev "$WIFI_INTERFACE" down 2>/dev/null || true
        ip addr flush dev "$WIFI_INTERFACE" 2>/dev/null || true
        ip addr add 192.168.100.1/24 dev "$WIFI_INTERFACE" 2>/dev/null || true
        ip link set dev "$WIFI_INTERFACE" up
        
        log_msg "WiFi configurado"
    else
        log_msg "AVISO: Interface WiFi não encontrada"
    fi
}

# Função para iniciar serviços com retry
start_services_with_retry() {
    log_msg "Iniciando serviços com retry automático..."
    
    local services=("tor" "hostapd" "dnsmasq")
    
    for service in "${services[@]}"; do
        log_msg "Iniciando $service..."
        
        local retry=0
        local success=false
        
        while [[ $retry -lt $MAX_RETRIES ]] && [[ "$success" == "false" ]]; do
            # Parar serviço se estiver rodando
            systemctl stop "$service" 2>/dev/null || true
            sleep 2
            
            # Iniciar serviço
            if systemctl start "$service" 2>/dev/null; then
                sleep 5
                
                # Verificar se está realmente ativo
                if systemctl is-active "$service" >/dev/null 2>&1; then
                    log_msg "$service iniciado com sucesso"
                    success=true
                else
                    log_msg "$service falhou na verificação de status"
                fi
            else
                log_msg "$service falhou ao iniciar"
            fi
            
            if [[ "$success" == "false" ]]; then
                retry=$((retry + 1))
                log_msg "Tentativa $retry/$MAX_RETRIES falhou para $service"
                
                if [[ $retry -lt $MAX_RETRIES ]]; then
                    log_msg "Aguardando ${RETRY_DELAY}s antes da próxima tentativa..."
                    sleep $RETRY_DELAY
                fi
            fi
        done
        
        if [[ "$success" == "false" ]]; then
            log_msg "ERRO: Falha ao iniciar $service após $MAX_RETRIES tentativas"
            # Continuar com outros serviços mesmo se um falhar
        fi
    done
}

# Função de verificação de saúde
health_check() {
    log_msg "Executando verificação de saúde..."
    
    local issues=0
    
    # Verificar serviços
    for service in tor hostapd dnsmasq; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            log_msg "✓ $service: ATIVO"
        else
            log_msg "✗ $service: INATIVO"
            issues=$((issues + 1))
        fi
    done
    
    # Verificar bridge
    if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
        log_msg "✓ Bridge: ATIVO"
    else
        log_msg "✗ Bridge: INATIVO"
        issues=$((issues + 1))
    fi
    
    # Verificar interfaces no bridge
    for iface in "${LAN_INTERFACES[@]}"; do
        if [[ -f "/sys/class/net/$iface/master" ]]; then
            local master=$(cat "/sys/class/net/$iface/master" 2>/dev/null | xargs basename 2>/dev/null || echo "")
            if [[ "$master" == "$BRIDGE_NAME" ]]; then
                log_msg "✓ $iface: NO BRIDGE"
            else
                log_msg "✗ $iface: FORA DO BRIDGE"
                issues=$((issues + 1))
            fi
        else
            log_msg "✗ $iface: SEM MASTER"
            issues=$((issues + 1))
        fi
    done
    
    if [[ $issues -eq 0 ]]; then
        log_msg "✓ VERIFICAÇÃO DE SAÚDE: TODOS OS COMPONENTES OK"
        return 0
    else
        log_msg "✗ VERIFICAÇÃO DE SAÚDE: $issues PROBLEMAS DETECTADOS"
        return 1
    fi
}

# Função principal
main() {
    log_msg "=== INICIANDO ROTEADOR TOR ROBUSTO ==="
    
    # Aguardar rede
    wait_for_network
    
    # Carregar configuração
    if ! load_config; then
        log_msg "ERRO CRÍTICO: Não foi possível carregar configuração"
        exit 1
    fi
    
    log_msg "Configuração:"
    log_msg "  WAN: $WAN_INTERFACE"
    log_msg "  WiFi: $WIFI_INTERFACE"
    log_msg "  Bridge: $BRIDGE_NAME"
    log_msg "  LAN: ${LAN_INTERFACES[*]}"
    
    # Configurar rede
    create_bridge_robust
    configure_wifi_robust
    
    # Configurar firewall
    if [[ -f "/opt/tor_router/setup_iptables.sh" ]]; then
        log_msg "Configurando firewall..."
        /opt/tor_router/setup_iptables.sh
    fi
    
    # Iniciar serviços
    start_services_with_retry
    
    # Aguardar estabilização
    log_msg "Aguardando estabilização do sistema..."
    sleep $HEALTH_CHECK_DELAY
    
    # Verificação de saúde
    if health_check; then
        log_msg "=== ROTEADOR TOR INICIADO COM SUCESSO ==="
        log_msg "SSID: TOR-K0K4-Network"
        log_msg "Senha: TorSecure2024!"
        log_msg "Gateway: 192.168.100.1"
    else
        log_msg "=== ROTEADOR TOR INICIADO COM PROBLEMAS ==="
        log_msg "Alguns componentes podem não estar funcionando corretamente"
    fi
    
    # Criar arquivo de status
    echo "$(date): Roteador TOR iniciado" > /tmp/tor_router_status
}

# Executar função principal
main "$@"
EOF

    chmod +x /opt/tor_router/start_tor_router_robust.sh
    success "Script de inicialização robusto criado"
}

# Função para criar script de monitoramento contínuo
create_monitoring_script() {
    log "Criando script de monitoramento contínuo..."
    
    cat > /opt/tor_router/monitor_tor_router.sh << 'EOF'
#!/bin/bash

# Monitor contínuo do Roteador TOR
# Executa verificações periódicas e auto-correção

CONFIG_FILE="/opt/tor_router_config.conf"
LOG_FILE="/var/log/tor_router_monitor.log"
CHECK_INTERVAL=300  # 5 minutos

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Carregar configuração
source "$CONFIG_FILE"

while true; do
    log_msg "Executando verificação de saúde..."
    
    # Verificar e corrigir serviços
    for service in tor hostapd dnsmasq; do
        if ! systemctl is-active "$service" >/dev/null 2>&1; then
            log_msg "PROBLEMA: $service não está ativo, tentando reiniciar..."
            systemctl restart "$service" 2>/dev/null || true
            sleep 5
            
            if systemctl is-active "$service" >/dev/null 2>&1; then
                log_msg "CORRIGIDO: $service reiniciado com sucesso"
            else
                log_msg "ERRO: Falha ao reiniciar $service"
            fi
        fi
    done
    
    # Verificar bridge
    if ! ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
        log_msg "PROBLEMA: Bridge não existe, recriando..."
        /opt/tor_router/start_tor_router_robust.sh
    fi
    
    # Verificar interfaces no bridge
    for iface in "${LAN_INTERFACES[@]}"; do
        if [[ -d "/sys/class/net/$iface" ]]; then
            if [[ ! -f "/sys/class/net/$iface/master" ]]; then
                log_msg "PROBLEMA: $iface fora do bridge, corrigindo..."
                ip link set dev "$iface" master "$BRIDGE_NAME" 2>/dev/null || true
            fi
        fi
    done
    
    log_msg "Verificação concluída, aguardando ${CHECK_INTERVAL}s..."
    sleep $CHECK_INTERVAL
done
EOF

    chmod +x /opt/tor_router/monitor_tor_router.sh
    success "Script de monitoramento criado"
}

# Função para criar serviço de monitoramento
create_monitoring_service() {
    log "Criando serviço de monitoramento..."
    
    cat > /etc/systemd/system/tor-router-monitor.service << 'EOF'
[Unit]
Description=TOR Router Monitor Service - Sistema K0K4
After=tor-router-robust.service
Wants=tor-router-robust.service

[Service]
Type=simple
ExecStart=/opt/tor_router/monitor_tor_router.sh
Restart=always
RestartSec=60
User=root

[Install]
WantedBy=multi-user.target
EOF

    success "Serviço de monitoramento criado"
}

# Função para habilitar serviços
enable_services() {
    log "Habilitando serviços para inicialização automática..."
    
    # Recarregar systemd
    systemctl daemon-reload
    
    # Habilitar serviços básicos
    systemctl enable tor 2>/dev/null || true
    systemctl enable hostapd 2>/dev/null || true
    systemctl enable dnsmasq 2>/dev/null || true
    
    # Habilitar serviços robustos
    systemctl enable tor-router-robust.service
    systemctl enable tor-router-monitor.service
    
    # Desabilitar serviços conflitantes
    systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true
    
    success "Serviços habilitados para inicialização automática"
}

# Função principal
main() {
    echo
    echo -e "${CYAN}============================================================================${NC}"
    echo -e "${CYAN}      CONFIGURANDO SISTEMA ROBUSTO DE INICIALIZAÇÃO AUTOMÁTICA${NC}"
    echo -e "${CYAN}============================================================================${NC}"
    echo
    
    # Verificar se é root
    if [[ $EUID -ne 0 ]]; then
        error "Este script deve ser executado como root!"
        exit 1
    fi
    
    # Verificar se diretório existe
    if [[ ! -d "/opt/tor_router" ]]; then
        log "Criando diretório /opt/tor_router..."
        mkdir -p /opt/tor_router
    fi
    
    # Criar componentes do sistema robusto
    create_robust_systemd_service
    create_robust_start_script
    create_monitoring_script
    create_monitoring_service
    enable_services
    
    echo
    echo -e "${CYAN}============================================================================${NC}"
    echo -e "${CYAN}                    CONFIGURAÇÃO CONCLUÍDA${NC}"
    echo -e "${CYAN}============================================================================${NC}"
    echo
    
    success "Sistema robusto de inicialização configurado!"
    echo
    info "Componentes criados:"
    info "  • Serviço principal: tor-router-robust.service"
    info "  • Serviço de monitoramento: tor-router-monitor.service"
    info "  • Script robusto: /opt/tor_router/start_tor_router_robust.sh"
    info "  • Monitor contínuo: /opt/tor_router/monitor_tor_router.sh"
    echo
    info "O sistema agora:"
    info "  ✓ Inicia automaticamente no boot"
    info "  ✓ Tem retry automático em caso de falha"
    info "  ✓ Monitora continuamente a saúde"
    info "  ✓ Auto-corrige problemas detectados"
    info "  ✓ Não trava o boot do sistema"
    echo
    info "Para testar agora: sudo systemctl start tor-router-robust.service"
    info "Para ver logs: sudo journalctl -u tor-router-robust.service -f"
}

# Executar função principal
main "$@"

