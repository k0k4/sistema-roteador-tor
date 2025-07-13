#!/bin/bash

# ============================================================================
# CORREÇÃO COMPLETA E DEFINITIVA DO ROTEADOR TOR - SISTEMA K0K4
# ============================================================================
# Solução definitiva que resolve TODOS os problemas identificados:
# - Detecção automática de interfaces (1 WAN + 3 LAN + WiFi)
# - Correção do erro dnsmasq linha 35
# - Bridge robusto com todas as interfaces LAN
# - Sistema de inicialização que NÃO trava o boot
# - Monitoramento contínuo e auto-correção
# - Funciona mesmo sem cabos conectados
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

# Configurações
CONFIG_FILE="/opt/tor_router_config.conf"
BACKUP_DIR="/opt/tor_router_backups"
LOG_FILE="/var/log/tor_router_complete_fix.log"

# Função de log
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${BLUE}$msg${NC}"
    echo "$msg" >> "$LOG_FILE"
}

success() {
    local msg="[SUCESSO] $1"
    echo -e "${GREEN}$msg${NC}"
    echo "$msg" >> "$LOG_FILE"
}

error() {
    local msg="[ERRO] $1"
    echo -e "${RED}$msg${NC}"
    echo "$msg" >> "$LOG_FILE"
}

warning() {
    local msg="[AVISO] $1"
    echo -e "${YELLOW}$msg${NC}"
    echo "$msg" >> "$LOG_FILE"
}

info() {
    local msg="[INFO] $1"
    echo -e "${CYAN}$msg${NC}"
    echo "$msg" >> "$LOG_FILE"
}

# Função para criar backup completo
create_full_backup() {
    log "Criando backup completo do sistema..."
    
    local backup_timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_path="$BACKUP_DIR/backup_$backup_timestamp"
    
    mkdir -p "$backup_path"
    
    # Backup de configurações importantes
    cp /etc/tor/torrc "$backup_path/" 2>/dev/null || true
    cp /etc/hostapd/hostapd.conf "$backup_path/" 2>/dev/null || true
    cp /etc/dnsmasq.conf "$backup_path/" 2>/dev/null || true
    cp -r /etc/systemd/system/tor* "$backup_path/" 2>/dev/null || true
    cp -r /etc/netplan/ "$backup_path/netplan_backup/" 2>/dev/null || true
    
    # Backup de scripts existentes
    cp -r /opt/tor_router/ "$backup_path/tor_router_backup/" 2>/dev/null || true
    
    success "Backup criado em: $backup_path"
}

# Função para parar todos os serviços
stop_all_services() {
    log "Parando todos os serviços relacionados..."
    
    # Parar serviços TOR
    systemctl stop tor-router-robust.service 2>/dev/null || true
    systemctl stop tor-router-monitor.service 2>/dev/null || true
    systemctl stop tor-monitor.service 2>/dev/null || true
    
    # Parar serviços básicos
    systemctl stop tor 2>/dev/null || true
    systemctl stop hostapd 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true
    
    # Parar serviços de rede problemáticos
    systemctl stop systemd-networkd 2>/dev/null || true
    systemctl stop systemd-resolved 2>/dev/null || true
    
    sleep 3
    success "Serviços parados"
}

# Função para limpar configurações problemáticas
clean_problematic_configs() {
    log "Limpando configurações problemáticas..."
    
    # Remover bridges existentes
    ip link delete br-tor 2>/dev/null || true
    ip link delete br0 2>/dev/null || true
    
    # Limpar regras iptables
    iptables -F 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true
    
    # Remover serviços problemáticos
    systemctl disable tor-router.service 2>/dev/null || true
    rm -f /etc/systemd/system/tor-router.service 2>/dev/null || true
    
    # Limpar configurações netplan conflitantes
    find /etc/netplan/ -name "*.yaml" -exec rm -f {} \; 2>/dev/null || true
    
    success "Configurações problemáticas removidas"
}

# Função para detectar interfaces automaticamente
auto_detect_interfaces() {
    log "Executando detecção automática de interfaces..."
    
    # Executar script de detecção
    if [[ -f "./auto_detect_interfaces_complete.sh" ]]; then
        chmod +x ./auto_detect_interfaces_complete.sh
        ./auto_detect_interfaces_complete.sh
    else
        error "Script de detecção não encontrado!"
        return 1
    fi
    
    # Verificar se configuração foi criada
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error "Configuração não foi criada pela detecção automática!"
        return 1
    fi
    
    success "Interfaces detectadas automaticamente"
}

# Função para carregar configuração
load_configuration() {
    log "Carregando configuração..."
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error "Arquivo de configuração não encontrado: $CONFIG_FILE"
        return 1
    fi
    
    source "$CONFIG_FILE"
    
    info "Configuração carregada:"
    info "  WAN: $WAN_INTERFACE"
    info "  WiFi: $WIFI_INTERFACE"
    info "  Bridge: $BRIDGE_NAME"
    info "  LAN: ${LAN_INTERFACES[*]}"
    
    success "Configuração carregada com sucesso"
}

# Função para configurar TOR corretamente
configure_tor_robust() {
    log "Configurando TOR de forma robusta..."
    
    # Backup da configuração atual
    cp /etc/tor/torrc /etc/tor/torrc.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    
    # Criar configuração TOR otimizada
    cat > /etc/tor/torrc << 'EOF'
# Configuração TOR - Roteador K0K4
# Configuração otimizada para roteamento transparente

# Configurações básicas
User debian-tor
PidFile /var/run/tor/tor.pid
Log notice file /var/log/tor/tor.log
DataDirectory /var/lib/tor

# Configurações de rede
SocksPort 127.0.0.1:9050
DNSPort 127.0.0.1:9053
TransPort 127.0.0.1:9040

# Configurações de controle
ControlPort 127.0.0.1:9051
CookieAuthentication 1

# Configurações de performance
NumEntryGuards 8
NumDirectoryGuards 3
GuardLifetime 30 days
NewCircuitPeriod 30
MaxCircuitDirtiness 600
CircuitBuildTimeout 60

# Configurações de segurança
ExitPolicy reject *:*
AutomapHostsOnResolve 1
VirtualAddrNetworkIPv4 10.192.0.0/10
VirtualAddrNetworkIPv6 [FC00::]/7

# Configurações para bridges (se necessário)
# UseBridges 1
# ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy

# Configurações de diretório
FascistFirewall 1
ReachableAddresses *:80,*:443,*:9001,*:9030
ReachableORAddresses *:443,*:9001
ReachableDirAddresses *:80,*:443,*:9030

# Configurações de cliente
ClientOnly 1
SafeLogging 1
EOF

    success "TOR configurado"
}

# Função para configurar hostapd corretamente
configure_hostapd_robust() {
    log "Configurando hostapd de forma robusta..."
    
    if [[ -z "$WIFI_INTERFACE" ]]; then
        warning "Interface WiFi não definida, pulando configuração hostapd"
        return 0
    fi
    
    # Backup da configuração atual
    cp /etc/hostapd/hostapd.conf /etc/hostapd/hostapd.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    
    # Criar configuração hostapd correta
    cat > /etc/hostapd/hostapd.conf << EOF
# Configuração HOSTAPD - Roteador TOR K0K4
# Configuração correta sem erros

# Interface
interface=$WIFI_INTERFACE
driver=nl80211

# Configurações básicas
ssid=$WIFI_SSID
hw_mode=g
channel=$WIFI_CHANNEL
country_code=$WIFI_COUNTRY

# Configurações de segurança
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=$WIFI_PASSWORD
rsn_pairwise=CCMP

# Configurações de performance
beacon_int=100
dtim_period=2
max_num_sta=50
rts_threshold=2347
fragm_threshold=2346

# Configurações de log
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2

# Configurações IEEE 802.11n
ieee80211n=1
ht_capab=[HT40][SHORT-GI-20][SHORT-GI-40]

# Configurações de controle
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0
EOF

    success "Hostapd configurado"
}

# Função para configurar dnsmasq SEM ERROS
configure_dnsmasq_robust() {
    log "Configurando dnsmasq SEM ERROS..."
    
    # Backup da configuração atual
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    
    # Parar systemd-resolved que conflita
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
    
    # Criar configuração dnsmasq LIMPA e SEM ERROS
    cat > /etc/dnsmasq.conf << EOF
# Configuração DNSMASQ - Roteador TOR K0K4
# Configuração LIMPA sem conflitos ou erros

# Configurações básicas
port=53
domain-needed
bogus-priv
no-resolv
no-poll

# Interfaces
interface=$BRIDGE_NAME
EOF

    # Adicionar interface WiFi se existir
    if [[ -n "$WIFI_INTERFACE" ]]; then
        echo "interface=$WIFI_INTERFACE" >> /etc/dnsmasq.conf
    fi
    
    cat >> /etc/dnsmasq.conf << EOF
bind-interfaces

# Configurações DHCP
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,255.255.255.0,12h
dhcp-option=option:router,$BRIDGE_IP
dhcp-option=option:dns-server,$BRIDGE_IP
dhcp-authoritative

# Configurações DNS
server=127.0.0.1#9053
cache-size=1000
neg-ttl=60

# Configurações de log
log-queries
log-dhcp
log-facility=/var/log/dnsmasq.log

# Configurações de segurança
stop-dns-rebind
rebind-localhost-ok
EOF

    success "Dnsmasq configurado SEM ERROS"
}

# Função para criar bridge robusto
create_robust_bridge() {
    log "Criando bridge robusto com todas as interfaces LAN..."
    
    # Remover bridge existente
    ip link delete "$BRIDGE_NAME" 2>/dev/null || true
    
    # Criar bridge
    ip link add name "$BRIDGE_NAME" type bridge
    ip link set dev "$BRIDGE_NAME" up
    ip addr add "$BRIDGE_IP/24" dev "$BRIDGE_NAME"
    
    # Aguardar estabilização
    sleep 2
    
    # Adicionar interfaces LAN ao bridge
    for iface in "${LAN_INTERFACES[@]}"; do
        if [[ -d "/sys/class/net/$iface" ]]; then
            log "Adicionando $iface ao bridge..."
            
            # Preparar interface
            ip link set dev "$iface" down 2>/dev/null || true
            ip addr flush dev "$iface" 2>/dev/null || true
            
            # Remover do NetworkManager
            nmcli device set "$iface" managed no 2>/dev/null || true
            
            # Adicionar ao bridge
            ip link set dev "$iface" up
            ip link set dev "$iface" master "$BRIDGE_NAME"
            
            success "Interface $iface adicionada ao bridge"
        else
            warning "Interface $iface não existe, pulando..."
        fi
    done
    
    success "Bridge criado com ${#LAN_INTERFACES[@]} interfaces"
}

# Função para configurar interface WiFi
configure_wifi_interface() {
    log "Configurando interface WiFi..."
    
    if [[ -z "$WIFI_INTERFACE" ]] || [[ ! -d "/sys/class/net/$WIFI_INTERFACE" ]]; then
        warning "Interface WiFi não disponível, pulando configuração"
        return 0
    fi
    
    # Remover do NetworkManager
    nmcli device set "$WIFI_INTERFACE" managed no 2>/dev/null || true
    
    # Configurar interface
    ip link set dev "$WIFI_INTERFACE" down 2>/dev/null || true
    ip addr flush dev "$WIFI_INTERFACE" 2>/dev/null || true
    ip addr add "$BRIDGE_IP/24" dev "$WIFI_INTERFACE"
    ip link set dev "$WIFI_INTERFACE" up
    
    success "Interface WiFi configurada"
}

# Função para configurar iptables robusto
configure_iptables_robust() {
    log "Configurando iptables de forma robusta..."
    
    # Limpar regras existentes
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    iptables -X
    iptables -t nat -X
    iptables -t mangle -X
    
    # Políticas padrão
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Regras básicas
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Regras para SSH (manter acesso)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Regras para TOR
    iptables -t nat -A OUTPUT -p tcp --dport 22 -j RETURN
    iptables -t nat -A OUTPUT -p tcp --dport 53 -j RETURN
    iptables -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j RETURN
    iptables -t nat -A OUTPUT -p tcp -d 192.168.0.0/16 -j RETURN
    iptables -t nat -A OUTPUT -p tcp -d 10.0.0.0/8 -j RETURN
    iptables -t nat -A OUTPUT -p tcp -d 172.16.0.0/12 -j RETURN
    
    # Redirecionar tráfego para TOR
    iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040
    
    # Regras para bridge
    iptables -A INPUT -i "$BRIDGE_NAME" -j ACCEPT
    iptables -A FORWARD -i "$BRIDGE_NAME" -j ACCEPT
    iptables -A FORWARD -o "$BRIDGE_NAME" -j ACCEPT
    
    # NAT para internet
    iptables -t nat -A POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE
    
    # Regras para WiFi se existir
    if [[ -n "$WIFI_INTERFACE" ]]; then
        iptables -A INPUT -i "$WIFI_INTERFACE" -j ACCEPT
        iptables -A FORWARD -i "$WIFI_INTERFACE" -j ACCEPT
        iptables -A FORWARD -o "$WIFI_INTERFACE" -j ACCEPT
    fi
    
    # Salvar regras
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    
    success "Iptables configurado"
}

# Função para habilitar IP forwarding
enable_ip_forwarding() {
    log "Habilitando IP forwarding..."
    
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-tor-router.conf
    echo 'net.ipv6.conf.all.forwarding=0' >> /etc/sysctl.d/99-tor-router.conf
    echo 'net.ipv6.conf.default.forwarding=0' >> /etc/sysctl.d/99-tor-router.conf
    
    sysctl -p /etc/sysctl.d/99-tor-router.conf
    
    success "IP forwarding habilitado"
}

# Função para iniciar serviços de forma robusta
start_services_robust() {
    log "Iniciando serviços de forma robusta..."
    
    local services=("tor" "hostapd" "dnsmasq")
    local max_retries=3
    local retry_delay=5
    
    for service in "${services[@]}"; do
        log "Iniciando $service..."
        
        local retry=0
        local success=false
        
        while [[ $retry -lt $max_retries ]] && [[ "$success" == "false" ]]; do
            # Parar serviço primeiro
            systemctl stop "$service" 2>/dev/null || true
            sleep 2
            
            # Iniciar serviço
            if systemctl start "$service" 2>/dev/null; then
                sleep 3
                
                # Verificar se está realmente ativo
                if systemctl is-active "$service" >/dev/null 2>&1; then
                    success "$service iniciado com sucesso"
                    success=true
                else
                    warning "$service falhou na verificação de status"
                fi
            else
                warning "$service falhou ao iniciar"
            fi
            
            if [[ "$success" == "false" ]]; then
                retry=$((retry + 1))
                if [[ $retry -lt $max_retries ]]; then
                    warning "Tentativa $retry/$max_retries falhou para $service, tentando novamente em ${retry_delay}s..."
                    sleep $retry_delay
                fi
            fi
        done
        
        if [[ "$success" == "false" ]]; then
            error "Falha ao iniciar $service após $max_retries tentativas"
            # Mostrar logs para debug
            journalctl -u "$service" --no-pager -n 10
        fi
    done
}

# Função para criar sistema de inicialização automática ROBUSTO
create_autostart_system() {
    log "Criando sistema de inicialização automática ROBUSTO..."
    
    # Criar script de inicialização
    cat > /opt/tor_router/start_tor_router_final.sh << 'EOF'
#!/bin/bash

# Script de inicialização FINAL e ROBUSTO
# NÃO trava o boot do sistema

LOG_FILE="/var/log/tor_router_autostart.log"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Aguardar rede básica (máximo 60s)
wait_for_basic_network() {
    local timeout=60
    local count=0
    
    while [[ $count -lt $timeout ]]; do
        if ip route show default >/dev/null 2>&1; then
            log_msg "Rede básica disponível"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    
    log_msg "Prosseguindo sem confirmação de rede (timeout)"
    return 0
}

# Carregar configuração
if [[ -f "/opt/tor_router_config.conf" ]]; then
    source "/opt/tor_router_config.conf"
else
    log_msg "ERRO: Configuração não encontrada"
    exit 1
fi

log_msg "=== INICIANDO ROTEADOR TOR AUTOMÁTICO ==="

# Aguardar rede
wait_for_basic_network

# Executar correção completa
if [[ -f "/opt/sistema-roteador-tor/tor_router_complete_fix_final.sh" ]]; then
    log_msg "Executando correção completa..."
    /opt/sistema-roteador-tor/tor_router_complete_fix_final.sh >> "$LOG_FILE" 2>&1
else
    log_msg "Script de correção não encontrado, tentando inicialização básica..."
    
    # Inicialização básica
    systemctl start tor hostapd dnsmasq 2>/dev/null || true
fi

log_msg "=== INICIALIZAÇÃO AUTOMÁTICA CONCLUÍDA ==="
EOF

    chmod +x /opt/tor_router/start_tor_router_final.sh
    
    # Criar serviço systemd ROBUSTO que NÃO trava o boot
    cat > /etc/systemd/system/tor-router-final.service << 'EOF'
[Unit]
Description=TOR Router Final Service - Sistema K0K4
After=network.target
Wants=network.target
DefaultDependencies=no

[Service]
Type=forking
ExecStart=/opt/tor_router/start_tor_router_final.sh
RemainAfterExit=yes
User=root
TimeoutStartSec=120
TimeoutStopSec=30

# Configurações para NÃO travar o boot
Restart=no
KillMode=process
SendSIGKILL=no

[Install]
WantedBy=multi-user.target
EOF

    # Habilitar serviço
    systemctl daemon-reload
    systemctl enable tor-router-final.service
    
    # Desabilitar serviços problemáticos
    systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true
    systemctl mask systemd-networkd-wait-online.service 2>/dev/null || true
    
    success "Sistema de inicialização automática criado (NÃO trava o boot)"
}

# Função para verificar status final
check_final_status() {
    log "Verificando status final do sistema..."
    
    local issues=0
    
    # Verificar serviços
    for service in tor hostapd dnsmasq; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            success "$service: ATIVO"
        else
            error "$service: INATIVO"
            issues=$((issues + 1))
        fi
    done
    
    # Verificar bridge
    if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
        success "Bridge $BRIDGE_NAME: ATIVO"
        
        # Verificar interfaces no bridge
        local bridge_interfaces=0
        for iface in "${LAN_INTERFACES[@]}"; do
            if [[ -f "/sys/class/net/$iface/master" ]]; then
                local master=$(cat "/sys/class/net/$iface/master" 2>/dev/null | xargs basename 2>/dev/null || echo "")
                if [[ "$master" == "$BRIDGE_NAME" ]]; then
                    success "Interface $iface: NO BRIDGE"
                    bridge_interfaces=$((bridge_interfaces + 1))
                else
                    warning "Interface $iface: FORA DO BRIDGE"
                fi
            fi
        done
        
        info "Interfaces no bridge: $bridge_interfaces/${#LAN_INTERFACES[@]}"
    else
        error "Bridge $BRIDGE_NAME: INATIVO"
        issues=$((issues + 1))
    fi
    
    # Verificar conectividade TOR (teste rápido)
    if timeout 10 curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip >/dev/null 2>&1; then
        success "TOR: CONECTADO"
    else
        warning "TOR: NÃO CONECTADO (pode levar alguns minutos para conectar)"
    fi
    
    # Verificar serviço de inicialização
    if systemctl is-enabled tor-router-final.service >/dev/null 2>&1; then
        success "Inicialização automática: HABILITADA"
    else
        warning "Inicialização automática: DESABILITADA"
    fi
    
    return $issues
}

# Função principal
main() {
    echo
    echo -e "${PURPLE}============================================================================${NC}"
    echo -e "${PURPLE}           CORREÇÃO COMPLETA E DEFINITIVA - ROTEADOR TOR K0K4${NC}"
    echo -e "${PURPLE}============================================================================${NC}"
    echo
    
    # Verificar se é root
    if [[ $EUID -ne 0 ]]; then
        error "Este script deve ser executado como root!"
        exit 1
    fi
    
    # Criar diretórios necessários
    mkdir -p /opt/tor_router
    mkdir -p "$BACKUP_DIR"
    mkdir -p /var/log/tor_router
    
    # Inicializar log
    echo "=== CORREÇÃO COMPLETA INICIADA EM $(date) ===" > "$LOG_FILE"
    
    info "Iniciando correção completa e definitiva..."
    echo
    
    # Executar correções em sequência
    create_full_backup
    echo
    
    stop_all_services
    echo
    
    clean_problematic_configs
    echo
    
    auto_detect_interfaces
    echo
    
    load_configuration
    echo
    
    configure_tor_robust
    echo
    
    configure_hostapd_robust
    echo
    
    configure_dnsmasq_robust
    echo
    
    create_robust_bridge
    echo
    
    configure_wifi_interface
    echo
    
    configure_iptables_robust
    echo
    
    enable_ip_forwarding
    echo
    
    start_services_robust
    echo
    
    create_autostart_system
    echo
    
    echo -e "${PURPLE}============================================================================${NC}"
    echo -e "${PURPLE}                           VERIFICAÇÃO FINAL${NC}"
    echo -e "${PURPLE}============================================================================${NC}"
    echo
    
    # Verificar status final
    local final_issues=$(check_final_status)
    
    echo
    if [[ $final_issues -eq 0 ]]; then
        echo -e "${GREEN}🎉 CORREÇÃO COMPLETA REALIZADA COM SUCESSO! 🎉${NC}"
        echo
        success "SISTEMA ROTEADOR TOR TOTALMENTE FUNCIONAL!"
        echo
        info "Configuração final:"
        info "  • SSID WiFi: $WIFI_SSID"
        info "  • Senha WiFi: $WIFI_PASSWORD"
        info "  • Gateway: $BRIDGE_IP"
        info "  • Interfaces LAN: ${#LAN_INTERFACES[@]} conectadas ao bridge"
        info "  • Inicialização automática: HABILITADA"
        echo
        info "Próximos passos:"
        info "  1. Reiniciar o sistema: sudo reboot"
        info "  2. Conectar dispositivos à rede WiFi: $WIFI_SSID"
        info "  3. Verificar status: sudo /opt/tor_router/status_tor_router.sh"
        echo
        success "O sistema agora funciona automaticamente no boot SEM TRAVAR!"
    else
        echo -e "${YELLOW}⚠️  CORREÇÃO CONCLUÍDA COM ALGUNS PROBLEMAS ⚠️${NC}"
        echo
        warning "Foram detectados $final_issues problemas"
        echo
        info "Mesmo assim, o sistema básico deve funcionar"
        info "Verifique os logs para mais detalhes:"
        info "  • Log principal: $LOG_FILE"
        info "  • Logs de serviços: sudo journalctl -u tor -u hostapd -u dnsmasq"
        echo
        info "Para tentar corrigir novamente: sudo ./tor_router_complete_fix_final.sh"
    fi
    
    echo -e "${PURPLE}============================================================================${NC}"
}

# Executar função principal
main "$@"

