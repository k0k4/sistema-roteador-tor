#!/bin/bash

# ============================================================================
# SISTEMA DE INICIALIZAÇÃO AUTOMÁTICA SUPER ROBUSTO - ROTEADOR TOR K0K4
# ============================================================================
# Cria sistema de inicialização que:
# - NÃO trava o boot do sistema
# - Tem retry automático em caso de falha
# - Monitora continuamente a saúde do sistema
# - Auto-corrige problemas detectados
# - Funciona mesmo com interfaces desconectadas
# ============================================================================

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
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

warning() {
    echo -e "${YELLOW}[AVISO]${NC} $1"
}

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Função para criar script de inicialização super robusto
create_super_robust_start_script() {
    log "Criando script de inicialização super robusto..."
    
    cat > /opt/tor_router/start_tor_router_super_robust.sh << 'EOF'
#!/bin/bash

# ============================================================================
# SCRIPT DE INICIALIZAÇÃO SUPER ROBUSTO - ROTEADOR TOR K0K4
# ============================================================================
# Este script é executado na inicialização do sistema e garante que:
# - O roteador TOR funcione mesmo com problemas de rede
# - Não trave o boot do sistema
# - Tenha retry automático
# - Funcione mesmo sem cabos conectados
# ============================================================================

# Configurações
CONFIG_FILE="/opt/tor_router_config.conf"
LOG_FILE="/var/log/tor_router_autostart.log"
PID_FILE="/var/run/tor_router_autostart.pid"
MAX_BOOT_WAIT=120  # Máximo 2 minutos para não travar o boot
MAX_RETRIES=5
RETRY_DELAY=10

# Função de log
log_msg() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" | tee -a "$LOG_FILE"
}

# Função para verificar se já está rodando
check_if_running() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log_msg "Script já está rodando (PID: $pid)"
            exit 0
        else
            rm -f "$PID_FILE"
        fi
    fi
    
    # Salvar PID atual
    echo $$ > "$PID_FILE"
}

# Função para aguardar rede básica (com timeout para não travar boot)
wait_for_basic_network() {
    log_msg "Aguardando rede básica (timeout: ${MAX_BOOT_WAIT}s)..."
    
    local count=0
    while [[ $count -lt $MAX_BOOT_WAIT ]]; do
        # Verificar se há pelo menos uma interface UP
        if ip link show | grep -q "state UP"; then
            log_msg "Interface de rede UP detectada"
            
            # Aguardar mais um pouco para estabilizar
            sleep 5
            return 0
        fi
        
        sleep 1
        count=$((count + 1))
        
        # Log a cada 30 segundos para não poluir
        if [[ $((count % 30)) -eq 0 ]]; then
            log_msg "Aguardando rede... ${count}s/${MAX_BOOT_WAIT}s"
        fi
    done
    
    log_msg "Timeout atingido, prosseguindo sem confirmação de rede"
    return 0
}

# Função para carregar configuração com fallback
load_config_with_fallback() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        log_msg "Configuração carregada: $CONFIG_FILE"
        return 0
    else
        log_msg "Configuração não encontrada, usando detecção automática..."
        
        # Detecção básica de emergência
        WAN_INTERFACE=$(ip route show default 2>/dev/null | head -1 | grep -o 'dev [^ ]*' | cut -d' ' -f2 || echo "")
        WIFI_INTERFACE=$(ls /sys/class/net/ | grep -E '^wl|^wlan' | head -1 || echo "")
        LAN_INTERFACES=($(ls /sys/class/net/ | grep -E '^en|^eth' | grep -v "$WAN_INTERFACE" || echo ""))
        BRIDGE_NAME="br-tor"
        BRIDGE_IP="192.168.100.1"
        
        log_msg "Configuração de emergência:"
        log_msg "  WAN: $WAN_INTERFACE"
        log_msg "  WiFi: $WIFI_INTERFACE"
        log_msg "  LAN: ${LAN_INTERFACES[*]}"
        
        return 0
    fi
}

# Função para criar bridge de forma robusta
create_bridge_robust() {
    log_msg "Criando bridge de forma robusta..."
    
    # Remover bridge existente se houver problemas
    ip link delete "$BRIDGE_NAME" 2>/dev/null || true
    sleep 1
    
    # Criar bridge
    if ip link add name "$BRIDGE_NAME" type bridge 2>/dev/null; then
        ip link set dev "$BRIDGE_NAME" up
        ip addr add "$BRIDGE_IP/24" dev "$BRIDGE_NAME" 2>/dev/null || true
        log_msg "Bridge $BRIDGE_NAME criado"
    else
        log_msg "ERRO: Falha ao criar bridge"
        return 1
    fi
    
    # Aguardar estabilização
    sleep 2
    
    # Adicionar interfaces LAN ao bridge (sem falhar se não conseguir)
    for iface in "${LAN_INTERFACES[@]}"; do
        if [[ -n "$iface" ]] && [[ -d "/sys/class/net/$iface" ]]; then
            log_msg "Tentando adicionar $iface ao bridge..."
            
            # Preparar interface (sem falhar se não conseguir)
            ip link set dev "$iface" down 2>/dev/null || true
            ip addr flush dev "$iface" 2>/dev/null || true
            nmcli device set "$iface" managed no 2>/dev/null || true
            
            # Adicionar ao bridge
            if ip link set dev "$iface" up 2>/dev/null && ip link set dev "$iface" master "$BRIDGE_NAME" 2>/dev/null; then
                log_msg "Interface $iface adicionada ao bridge"
            else
                log_msg "AVISO: Não foi possível adicionar $iface ao bridge (normal se cabo desconectado)"
            fi
        fi
    done
    
    return 0
}

# Função para configurar WiFi de forma robusta
configure_wifi_robust() {
    if [[ -n "$WIFI_INTERFACE" ]] && [[ -d "/sys/class/net/$WIFI_INTERFACE" ]]; then
        log_msg "Configurando WiFi: $WIFI_INTERFACE"
        
        # Remover do NetworkManager
        nmcli device set "$WIFI_INTERFACE" managed no 2>/dev/null || true
        
        # Configurar interface
        ip link set dev "$WIFI_INTERFACE" down 2>/dev/null || true
        ip addr flush dev "$WIFI_INTERFACE" 2>/dev/null || true
        ip addr add "$BRIDGE_IP/24" dev "$WIFI_INTERFACE" 2>/dev/null || true
        ip link set dev "$WIFI_INTERFACE" up 2>/dev/null || true
        
        log_msg "WiFi configurado"
    else
        log_msg "Interface WiFi não disponível"
    fi
}

# Função para configurar iptables básico
configure_basic_iptables() {
    log_msg "Configurando iptables básico..."
    
    # Regras básicas para não quebrar conectividade
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    
    # Habilitar forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    
    # NAT básico se WAN interface existir
    if [[ -n "$WAN_INTERFACE" ]] && [[ -d "/sys/class/net/$WAN_INTERFACE" ]]; then
        iptables -t nat -A POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE 2>/dev/null || true
        log_msg "NAT configurado para $WAN_INTERFACE"
    fi
    
    log_msg "Iptables básico configurado"
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
            # Parar serviço primeiro
            systemctl stop "$service" 2>/dev/null || true
            sleep 2
            
            # Tentar iniciar
            if systemctl start "$service" 2>/dev/null; then
                sleep 3
                
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
                if [[ $retry -lt $MAX_RETRIES ]]; then
                    log_msg "Tentativa $retry/$MAX_RETRIES falhou para $service, aguardando ${RETRY_DELAY}s..."
                    sleep $RETRY_DELAY
                fi
            fi
        done
        
        if [[ "$success" == "false" ]]; then
            log_msg "ERRO: Falha ao iniciar $service após $MAX_RETRIES tentativas"
            # Continuar com outros serviços
        fi
    done
}

# Função para verificação de saúde básica
basic_health_check() {
    log_msg "Executando verificação de saúde básica..."
    
    local issues=0
    
    # Verificar bridge
    if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
        log_msg "✓ Bridge: OK"
    else
        log_msg "✗ Bridge: PROBLEMA"
        issues=$((issues + 1))
    fi
    
    # Verificar serviços críticos
    for service in tor; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            log_msg "✓ $service: OK"
        else
            log_msg "✗ $service: PROBLEMA"
            issues=$((issues + 1))
        fi
    done
    
    # Verificar conectividade básica (teste rápido)
    if timeout 5 ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log_msg "✓ Conectividade: OK"
    else
        log_msg "✗ Conectividade: PROBLEMA"
        issues=$((issues + 1))
    fi
    
    log_msg "Verificação concluída: $issues problemas detectados"
    return $issues
}

# Função para limpeza na saída
cleanup() {
    log_msg "Limpando recursos..."
    rm -f "$PID_FILE"
}

# Configurar trap para limpeza
trap cleanup EXIT

# Função principal
main() {
    log_msg "=== INICIANDO ROTEADOR TOR SUPER ROBUSTO ==="
    
    # Verificar se já está rodando
    check_if_running
    
    # Aguardar rede básica (com timeout)
    wait_for_basic_network
    
    # Carregar configuração
    load_config_with_fallback
    
    # Configurar rede
    create_bridge_robust
    configure_wifi_robust
    configure_basic_iptables
    
    # Iniciar serviços
    start_services_with_retry
    
    # Verificação de saúde
    if basic_health_check; then
        log_msg "=== ROTEADOR TOR INICIADO COM SUCESSO ==="
    else
        log_msg "=== ROTEADOR TOR INICIADO COM ALGUNS PROBLEMAS ==="
    fi
    
    # Criar arquivo de status
    echo "$(date): Roteador TOR iniciado automaticamente" > /tmp/tor_router_autostart_status
    
    log_msg "Inicialização automática concluída"
}

# Executar função principal
main "$@"
EOF

    chmod +x /opt/tor_router/start_tor_router_super_robust.sh
    success "Script de inicialização super robusto criado"
}

# Função para criar script de monitoramento contínuo
create_continuous_monitoring_script() {
    log "Criando script de monitoramento contínuo..."
    
    cat > /opt/tor_router/monitor_tor_router_continuous.sh << 'EOF'
#!/bin/bash

# ============================================================================
# MONITORAMENTO CONTÍNUO SUPER ROBUSTO - ROTEADOR TOR K0K4
# ============================================================================
# Monitora continuamente o sistema e corrige problemas automaticamente
# ============================================================================

CONFIG_FILE="/opt/tor_router_config.conf"
LOG_FILE="/var/log/tor_router_monitor.log"
PID_FILE="/var/run/tor_router_monitor.pid"
CHECK_INTERVAL=300  # 5 minutos
QUICK_CHECK_INTERVAL=60  # 1 minuto para verificações rápidas

log_msg() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" | tee -a "$LOG_FILE"
}

# Verificar se já está rodando
if [[ -f "$PID_FILE" ]]; then
    local pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
        log_msg "Monitor já está rodando (PID: $pid)"
        exit 0
    else
        rm -f "$PID_FILE"
    fi
fi

# Salvar PID atual
echo $$ > "$PID_FILE"

# Carregar configuração
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    log_msg "ERRO: Configuração não encontrada"
    exit 1
fi

# Função de limpeza
cleanup() {
    log_msg "Parando monitor..."
    rm -f "$PID_FILE"
    exit 0
}

trap cleanup SIGTERM SIGINT

log_msg "=== INICIANDO MONITORAMENTO CONTÍNUO ==="

# Loop principal de monitoramento
while true; do
    log_msg "Executando verificação de saúde..."
    
    local problems_fixed=0
    
    # Verificar e corrigir serviços
    for service in tor hostapd dnsmasq; do
        if ! systemctl is-active "$service" >/dev/null 2>&1; then
            log_msg "PROBLEMA: $service não está ativo, tentando reiniciar..."
            
            if systemctl restart "$service" 2>/dev/null; then
                sleep 5
                if systemctl is-active "$service" >/dev/null 2>&1; then
                    log_msg "CORRIGIDO: $service reiniciado com sucesso"
                    problems_fixed=$((problems_fixed + 1))
                else
                    log_msg "ERRO: Falha ao reiniciar $service"
                fi
            else
                log_msg "ERRO: Falha ao tentar reiniciar $service"
            fi
        fi
    done
    
    # Verificar bridge
    if ! ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
        log_msg "PROBLEMA: Bridge não existe, recriando..."
        
        # Recriar bridge
        ip link add name "$BRIDGE_NAME" type bridge 2>/dev/null || true
        ip link set dev "$BRIDGE_NAME" up 2>/dev/null || true
        ip addr add "$BRIDGE_IP/24" dev "$BRIDGE_NAME" 2>/dev/null || true
        
        # Readicionar interfaces
        for iface in "${LAN_INTERFACES[@]}"; do
            if [[ -d "/sys/class/net/$iface" ]]; then
                ip link set dev "$iface" master "$BRIDGE_NAME" 2>/dev/null || true
            fi
        done
        
        log_msg "CORRIGIDO: Bridge recriado"
        problems_fixed=$((problems_fixed + 1))
    fi
    
    # Verificar interfaces no bridge
    for iface in "${LAN_INTERFACES[@]}"; do
        if [[ -d "/sys/class/net/$iface" ]]; then
            if [[ ! -f "/sys/class/net/$iface/master" ]]; then
                log_msg "PROBLEMA: $iface fora do bridge, corrigindo..."
                ip link set dev "$iface" master "$BRIDGE_NAME" 2>/dev/null || true
                problems_fixed=$((problems_fixed + 1))
            fi
        fi
    done
    
    # Verificar conectividade TOR (teste rápido)
    if ! timeout 10 curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip >/dev/null 2>&1; then
        log_msg "PROBLEMA: TOR não conectado, tentando reconectar..."
        
        # Tentar reconectar TOR
        systemctl restart tor 2>/dev/null || true
        sleep 10
        
        if timeout 10 curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip >/dev/null 2>&1; then
            log_msg "CORRIGIDO: TOR reconectado"
            problems_fixed=$((problems_fixed + 1))
        else
            log_msg "AVISO: TOR ainda não conectado (pode levar mais tempo)"
        fi
    fi
    
    if [[ $problems_fixed -gt 0 ]]; then
        log_msg "Verificação concluída: $problems_fixed problemas corrigidos"
    else
        log_msg "Verificação concluída: sistema funcionando normalmente"
    fi
    
    # Aguardar próxima verificação
    sleep $CHECK_INTERVAL
done
EOF

    chmod +x /opt/tor_router/monitor_tor_router_continuous.sh
    success "Script de monitoramento contínuo criado"
}

# Função para criar serviços systemd robustos
create_robust_systemd_services() {
    log "Criando serviços systemd robustos..."
    
    # Serviço principal de inicialização
    cat > /etc/systemd/system/tor-router-super-robust.service << 'EOF'
[Unit]
Description=TOR Router Super Robust Service - Sistema K0K4
After=network.target
Wants=network.target
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/opt/tor_router/start_tor_router_super_robust.sh
RemainAfterExit=yes
User=root

# Configurações para NÃO travar o boot
TimeoutStartSec=150
TimeoutStopSec=30
Restart=no
KillMode=process
SendSIGKILL=no

# Configurações de segurança
PrivateNetwork=no
ProtectSystem=no
ProtectHome=no

[Install]
WantedBy=multi-user.target
EOF

    # Serviço de monitoramento contínuo
    cat > /etc/systemd/system/tor-router-monitor-continuous.service << 'EOF'
[Unit]
Description=TOR Router Continuous Monitor Service - Sistema K0K4
After=tor-router-super-robust.service
Wants=tor-router-super-robust.service
Requisite=tor-router-super-robust.service

[Service]
Type=simple
ExecStart=/opt/tor_router/monitor_tor_router_continuous.sh
Restart=always
RestartSec=60
User=root

# Configurações de segurança
PrivateNetwork=no
ProtectSystem=no
ProtectHome=no

[Install]
WantedBy=multi-user.target
EOF

    success "Serviços systemd robustos criados"
}

# Função para criar script de status melhorado
create_improved_status_script() {
    log "Criando script de status melhorado..."
    
    cat > /opt/tor_router/status_tor_router_improved.sh << 'EOF'
#!/bin/bash

# ============================================================================
# STATUS MELHORADO DO ROTEADOR TOR - SISTEMA K0K4
# ============================================================================

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

CONFIG_FILE="/opt/tor_router_config.conf"

# Carregar configuração
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    echo -e "${RED}ERRO: Configuração não encontrada${NC}"
    exit 1
fi

echo
echo -e "${CYAN}============================================================================${NC}"
echo -e "${CYAN}              STATUS COMPLETO DO ROTEADOR TOR - SISTEMA K0K4${NC}"
echo -e "${CYAN}============================================================================${NC}"
echo

# Status dos serviços
echo -e "${BLUE}SERVIÇOS:${NC}"
for service in tor hostapd dnsmasq; do
    if systemctl is-active "$service" >/dev/null 2>&1; then
        echo -e "  • $service: ${GREEN}ATIVO${NC}"
    else
        echo -e "  • $service: ${RED}INATIVO${NC}"
    fi
done

# Status dos serviços de inicialização
echo
echo -e "${BLUE}SERVIÇOS DE INICIALIZAÇÃO:${NC}"
for service in tor-router-super-robust tor-router-monitor-continuous; do
    if systemctl is-enabled "$service" >/dev/null 2>&1; then
        local status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
        if [[ "$status" == "active" ]]; then
            echo -e "  • $service: ${GREEN}HABILITADO E ATIVO${NC}"
        else
            echo -e "  • $service: ${YELLOW}HABILITADO MAS INATIVO${NC}"
        fi
    else
        echo -e "  • $service: ${RED}DESABILITADO${NC}"
    fi
done

# Status das interfaces
echo
echo -e "${BLUE}INTERFACES:${NC}"
echo -e "  • WAN (Internet): $WAN_INTERFACE"
if [[ -d "/sys/class/net/$WAN_INTERFACE" ]]; then
    local wan_status=$(cat "/sys/class/net/$WAN_INTERFACE/operstate" 2>/dev/null || echo "unknown")
    local wan_ip=$(ip addr show "$WAN_INTERFACE" | grep "inet " | awk '{print $2}' | head -1)
    echo -e "    Status: $wan_status"
    if [[ -n "$wan_ip" ]]; then
        echo -e "    IP: ${GREEN}$wan_ip${NC}"
    else
        echo -e "    IP: ${RED}Não configurado${NC}"
    fi
else
    echo -e "    ${RED}Interface não existe${NC}"
fi

echo -e "  • WiFi (Hotspot): $WIFI_INTERFACE"
if [[ -n "$WIFI_INTERFACE" ]] && [[ -d "/sys/class/net/$WIFI_INTERFACE" ]]; then
    local wifi_status=$(cat "/sys/class/net/$WIFI_INTERFACE/operstate" 2>/dev/null || echo "unknown")
    echo -e "    Status: $wifi_status"
    if systemctl is-active hostapd >/dev/null 2>&1; then
        echo -e "    Hotspot: ${GREEN}ATIVO${NC}"
    else
        echo -e "    Hotspot: ${RED}INATIVO${NC}"
    fi
else
    echo -e "    ${YELLOW}Interface não disponível${NC}"
fi

echo -e "  • Bridge: $BRIDGE_NAME"
if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
    local bridge_ip=$(ip addr show "$BRIDGE_NAME" | grep "inet " | awk '{print $2}' | head -1)
    echo -e "    Status: ${GREEN}ATIVO${NC}"
    echo -e "    IP: $bridge_ip"
    
    # Interfaces no bridge
    local bridge_interfaces=0
    echo -e "    Interfaces LAN no bridge:"
    for iface in "${LAN_INTERFACES[@]}"; do
        if [[ -f "/sys/class/net/$iface/master" ]]; then
            local master=$(cat "/sys/class/net/$iface/master" 2>/dev/null | xargs basename 2>/dev/null || echo "")
            if [[ "$master" == "$BRIDGE_NAME" ]]; then
                echo -e "      • $iface: ${GREEN}CONECTADO${NC}"
                bridge_interfaces=$((bridge_interfaces + 1))
            else
                echo -e "      • $iface: ${YELLOW}FORA DO BRIDGE${NC}"
            fi
        else
            echo -e "      • $iface: ${RED}SEM MASTER${NC}"
        fi
    done
    echo -e "    Total no bridge: $bridge_interfaces/${#LAN_INTERFACES[@]}"
else
    echo -e "    Status: ${RED}INATIVO${NC}"
fi

# Conectividade TOR
echo
echo -e "${BLUE}CONECTIVIDADE TOR:${NC}"
if timeout 10 curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip >/dev/null 2>&1; then
    local tor_ip=$(timeout 10 curl -s --socks5 127.0.0.1:9050 https://ipinfo.io/ip 2>/dev/null || echo "Desconhecido")
    echo -e "  • Status: ${GREEN}CONECTADO${NC}"
    echo -e "  • IP TOR: $tor_ip"
    
    # Informações adicionais do IP TOR
    local tor_info=$(timeout 10 curl -s --socks5 127.0.0.1:9050 https://ipinfo.io/json 2>/dev/null)
    if [[ -n "$tor_info" ]]; then
        local country=$(echo "$tor_info" | grep -o '"country":"[^"]*' | cut -d'"' -f4)
        local city=$(echo "$tor_info" | grep -o '"city":"[^"]*' | cut -d'"' -f4)
        local org=$(echo "$tor_info" | grep -o '"org":"[^"]*' | cut -d'"' -f4)
        
        if [[ -n "$country" ]]; then
            echo -e "  • País: $country"
        fi
        if [[ -n "$city" ]]; then
            echo -e "  • Cidade: $city"
        fi
        if [[ -n "$org" ]]; then
            echo -e "  • Provedor: $org"
        fi
    fi
else
    echo -e "  • Status: ${RED}NÃO CONECTADO${NC}"
    echo -e "  • ${YELLOW}TOR pode levar alguns minutos para conectar${NC}"
fi

# Dispositivos conectados
echo
echo -e "${BLUE}DISPOSITIVOS CONECTADOS:${NC}"
local connected_devices=0
if [[ -f "/var/lib/dhcp/dhcpd.leases" ]]; then
    connected_devices=$(grep "binding state active" /var/lib/dhcp/dhcpd.leases 2>/dev/null | wc -l)
elif [[ -f "/var/lib/dhcpcd5/dhcpcd.leases" ]]; then
    connected_devices=$(wc -l < /var/lib/dhcpcd5/dhcpcd.leases 2>/dev/null || echo 0)
else
    # Contar por ARP
    connected_devices=$(arp -a | grep -c "192.168.100" 2>/dev/null || echo 0)
fi

echo -e "  • Total de dispositivos: $connected_devices"

# Informações de rede WiFi
if [[ -n "$WIFI_INTERFACE" ]] && systemctl is-active hostapd >/dev/null 2>&1; then
    echo
    echo -e "${BLUE}REDE WIFI:${NC}"
    echo -e "  • SSID: ${GREEN}$WIFI_SSID${NC}"
    echo -e "  • Senha: $WIFI_PASSWORD"
    echo -e "  • Canal: $WIFI_CHANNEL"
    echo -e "  • Gateway: $BRIDGE_IP"
fi

# Logs recentes
echo
echo -e "${BLUE}LOGS RECENTES:${NC}"
if [[ -f "/var/log/tor_router_autostart.log" ]]; then
    echo -e "  • Últimas 3 linhas do log de inicialização:"
    tail -3 /var/log/tor_router_autostart.log | sed 's/^/    /'
fi

if [[ -f "/var/log/tor_router_monitor.log" ]]; then
    echo -e "  • Últimas 3 linhas do log de monitoramento:"
    tail -3 /var/log/tor_router_monitor.log | sed 's/^/    /'
fi

echo
echo -e "${CYAN}============================================================================${NC}"

# Resumo final
local total_issues=0

# Contar problemas
for service in tor hostapd dnsmasq; do
    if ! systemctl is-active "$service" >/dev/null 2>&1; then
        total_issues=$((total_issues + 1))
    fi
done

if ! ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
    total_issues=$((total_issues + 1))
fi

if ! timeout 5 curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip >/dev/null 2>&1; then
    total_issues=$((total_issues + 1))
fi

if [[ $total_issues -eq 0 ]]; then
    echo -e "${GREEN}✅ SISTEMA FUNCIONANDO PERFEITAMENTE!${NC}"
else
    echo -e "${YELLOW}⚠️  SISTEMA COM $total_issues PROBLEMAS DETECTADOS${NC}"
    echo -e "${CYAN}Execute: sudo /opt/tor_router/start_tor_router_super_robust.sh${NC}"
fi

echo
EOF

    chmod +x /opt/tor_router/status_tor_router_improved.sh
    success "Script de status melhorado criado"
}

# Função para configurar sistema de inicialização
configure_autostart_system() {
    log "Configurando sistema de inicialização automática..."
    
    # Recarregar systemd
    systemctl daemon-reload
    
    # Habilitar serviços
    systemctl enable tor-router-super-robust.service
    systemctl enable tor-router-monitor-continuous.service
    
    # Habilitar serviços básicos
    systemctl enable tor 2>/dev/null || true
    systemctl enable hostapd 2>/dev/null || true
    systemctl enable dnsmasq 2>/dev/null || true
    
    # Desabilitar serviços problemáticos que podem travar o boot
    systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true
    systemctl mask systemd-networkd-wait-online.service 2>/dev/null || true
    
    # Desabilitar serviços conflitantes
    systemctl disable systemd-resolved 2>/dev/null || true
    systemctl stop systemd-resolved 2>/dev/null || true
    
    success "Sistema de inicialização configurado"
}

# Função para criar comandos de conveniência
create_convenience_commands() {
    log "Criando comandos de conveniência..."
    
    # Comando tor-router-status
    cat > /usr/local/bin/tor-router-status << 'EOF'
#!/bin/bash
/opt/tor_router/status_tor_router_improved.sh
EOF
    chmod +x /usr/local/bin/tor-router-status
    
    # Comando tor-router-start
    cat > /usr/local/bin/tor-router-start << 'EOF'
#!/bin/bash
echo "Iniciando Roteador TOR..."
systemctl start tor-router-super-robust.service
systemctl start tor-router-monitor-continuous.service
echo "Aguarde alguns segundos e execute: tor-router-status"
EOF
    chmod +x /usr/local/bin/tor-router-start
    
    # Comando tor-router-stop
    cat > /usr/local/bin/tor-router-stop << 'EOF'
#!/bin/bash
echo "Parando Roteador TOR..."
systemctl stop tor-router-monitor-continuous.service
systemctl stop tor-router-super-robust.service
systemctl stop tor hostapd dnsmasq
echo "Roteador TOR parado"
EOF
    chmod +x /usr/local/bin/tor-router-stop
    
    # Comando tor-router-restart
    cat > /usr/local/bin/tor-router-restart << 'EOF'
#!/bin/bash
echo "Reiniciando Roteador TOR..."
tor-router-stop
sleep 3
tor-router-start
EOF
    chmod +x /usr/local/bin/tor-router-restart
    
    success "Comandos de conveniência criados"
}

# Função principal
main() {
    echo
    echo -e "${PURPLE}============================================================================${NC}"
    echo -e "${PURPLE}        CRIANDO SISTEMA DE INICIALIZAÇÃO AUTOMÁTICA SUPER ROBUSTO${NC}"
    echo -e "${PURPLE}============================================================================${NC}"
    echo
    
    # Verificar se é root
    if [[ $EUID -ne 0 ]]; then
        error "Este script deve ser executado como root!"
        exit 1
    fi
    
    # Criar diretórios necessários
    mkdir -p /opt/tor_router
    mkdir -p /var/log/tor_router
    
    info "Criando sistema de inicialização automática que:"
    info "  • NÃO trava o boot do sistema"
    info "  • Tem retry automático em caso de falha"
    info "  • Monitora continuamente a saúde"
    info "  • Auto-corrige problemas detectados"
    info "  • Funciona mesmo com interfaces desconectadas"
    echo
    
    # Criar componentes do sistema
    create_super_robust_start_script
    echo
    
    create_continuous_monitoring_script
    echo
    
    create_robust_systemd_services
    echo
    
    create_improved_status_script
    echo
    
    configure_autostart_system
    echo
    
    create_convenience_commands
    echo
    
    echo -e "${PURPLE}============================================================================${NC}"
    echo -e "${PURPLE}                    SISTEMA DE INICIALIZAÇÃO CRIADO${NC}"
    echo -e "${PURPLE}============================================================================${NC}"
    echo
    
    success "Sistema de inicialização automática super robusto criado!"
    echo
    info "Componentes criados:"
    info "  • Serviço principal: tor-router-super-robust.service"
    info "  • Serviço de monitoramento: tor-router-monitor-continuous.service"
    info "  • Script robusto: /opt/tor_router/start_tor_router_super_robust.sh"
    info "  • Monitor contínuo: /opt/tor_router/monitor_tor_router_continuous.sh"
    info "  • Status melhorado: /opt/tor_router/status_tor_router_improved.sh"
    echo
    
    info "Comandos disponíveis:"
    info "  • tor-router-status   - Ver status completo"
    info "  • tor-router-start    - Iniciar roteador"
    info "  • tor-router-stop     - Parar roteador"
    info "  • tor-router-restart  - Reiniciar roteador"
    echo
    
    info "Características do sistema:"
    info "  ✓ Inicialização automática no boot (SEM TRAVAR)"
    info "  ✓ Retry automático em caso de falha"
    info "  ✓ Monitoramento contínuo (5 em 5 minutos)"
    info "  ✓ Auto-correção de problemas"
    info "  ✓ Funciona mesmo sem cabos conectados"
    info "  ✓ Timeout de boot configurado (150s máximo)"
    info "  ✓ Logs detalhados para debug"
    echo
    
    success "SISTEMA PRONTO! Agora execute a correção completa:"
    info "sudo ./tor_router_complete_fix_final.sh"
    
    echo -e "${PURPLE}============================================================================${NC}"
}

# Executar função principal
main "$@"

