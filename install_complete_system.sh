#!/bin/bash

# ============================================================================
# Script de Instalação Completa do Sistema Roteador TOR
# Sistema: Linux Lite 7.4 / Ubuntu 24.04
# Autor: Manus AI
# Versão: 1.0
# 
# Este script automatiza completamente a instalação do sistema roteador TOR
# ============================================================================

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Função para log
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERRO] $1${NC}"
    exit 1
}

warning() {
    echo -e "${YELLOW}[AVISO] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

success() {
    echo -e "${PURPLE}[SUCESSO] $1${NC}"
}

header() {
    echo -e "${CYAN}$1${NC}"
}

# Banner de apresentação
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "============================================================================"
    echo "                    SISTEMA ROTEADOR TOR - INSTALAÇÃO COMPLETA"
    echo "============================================================================"
    echo "Sistema: Linux Lite 7.4 / Ubuntu 24.04"
    echo "Versão: 1.0"
    echo "Autor: Manus AI"
    echo "Data: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "============================================================================"
    echo -e "${NC}"
    echo
}

# Verificar pré-requisitos
check_prerequisites() {
    header "=== VERIFICANDO PRÉ-REQUISITOS ==="
    
    # Verificar se está rodando como root
    if [[ $EUID -ne 0 ]]; then
        error "Este script deve ser executado como root (sudo)"
    fi
    
    # Verificar sistema operacional
    if ! grep -q "Ubuntu\|Linux Lite" /etc/os-release; then
        warning "Sistema não testado. Recomendado: Ubuntu 24.04 ou Linux Lite 7.4"
        read -p "Continuar mesmo assim? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Verificar conexão com internet
    if ! ping -c 1 google.com &> /dev/null; then
        error "Sem conexão com a internet. Conecte-se à internet e tente novamente."
    fi
    
    # Verificar espaço em disco
    available_space=$(df / | awk 'NR==2 {print $4}')
    required_space=5242880  # 5GB em KB
    
    if [[ $available_space -lt $required_space ]]; then
        error "Espaço insuficiente. Necessário: 5GB, Disponível: $((available_space/1024/1024))GB"
    fi
    
    # Verificar interfaces de rede
    if ! ip link show | grep -q "wlan0"; then
        warning "Interface WiFi (wlan0) não encontrada. Verifique se o adaptador WiFi está conectado."
    fi
    
    success "Pré-requisitos verificados com sucesso!"
    echo
}

# Configurar parâmetros
configure_parameters() {
    header "=== CONFIGURAÇÃO DE PARÂMETROS ==="
    
    echo "Configure os parâmetros do seu roteador TOR:"
    echo
    
    # SSID WiFi
    read -p "Nome da rede WiFi [TOR_Router_Secure]: " WIFI_SSID
    WIFI_SSID=${WIFI_SSID:-TOR_Router_Secure}
    
    # Senha WiFi
    while true; do
        read -s -p "Senha da rede WiFi [TorSecure2024!]: " WIFI_PASSWORD
        WIFI_PASSWORD=${WIFI_PASSWORD:-TorSecure2024!}
        echo
        
        if [[ ${#WIFI_PASSWORD} -ge 8 ]]; then
            break
        else
            echo "Senha deve ter pelo menos 8 caracteres!"
        fi
    done
    
    # Canal WiFi
    read -p "Canal WiFi [6]: " WIFI_CHANNEL
    WIFI_CHANNEL=${WIFI_CHANNEL:-6}
    
    # Rede interna
    read -p "Rede interna [192.168.100.0/24]: " INTERNAL_NETWORK
    INTERNAL_NETWORK=${INTERNAL_NETWORK:-192.168.100.0/24}
    
    # Gateway IP
    read -p "IP do gateway [192.168.100.1]: " GATEWAY_IP
    GATEWAY_IP=${GATEWAY_IP:-192.168.100.1}
    
    # Interface de internet
    echo
    echo "Interfaces de rede disponíveis:"
    ip link show | grep -E "^[0-9]+:" | grep -v "lo:" | awk -F': ' '{print "  " $2}' | sed 's/@.*//'
    echo
    read -p "Interface de internet [eth0]: " INTERNET_INTERFACE
    INTERNET_INTERFACE=${INTERNET_INTERFACE:-eth0}
    
    # Interface WiFi
    read -p "Interface WiFi [wlan0]: " WIFI_INTERFACE
    WIFI_INTERFACE=${WIFI_INTERFACE:-wlan0}
    
    # Interface LAN (opcional)
    read -p "Interface LAN [eth1] (deixe vazio se não usar): " LAN_INTERFACE
    LAN_INTERFACE=${LAN_INTERFACE:-eth1}
    
    # Bridges TOR
    echo
    echo "Configuração de Bridges TOR:"
    echo "1) Sem bridges (padrão)"
    echo "2) Bridges obfs4 (recomendado para países com censura)"
    echo "3) Bridges snowflake (alternativa)"
    read -p "Escolha [1]: " BRIDGE_CHOICE
    BRIDGE_CHOICE=${BRIDGE_CHOICE:-1}
    
    case $BRIDGE_CHOICE in
        1) BRIDGE_TYPE="none" ;;
        2) BRIDGE_TYPE="obfs4" ;;
        3) BRIDGE_TYPE="snowflake" ;;
        *) BRIDGE_TYPE="none" ;;
    esac
    
    echo
    success "Parâmetros configurados:"
    info "SSID WiFi: $WIFI_SSID"
    info "Canal WiFi: $WIFI_CHANNEL"
    info "Rede interna: $INTERNAL_NETWORK"
    info "Gateway: $GATEWAY_IP"
    info "Interface internet: $INTERNET_INTERFACE"
    info "Interface WiFi: $WIFI_INTERFACE"
    info "Interface LAN: $LAN_INTERFACE"
    info "Bridges: $BRIDGE_TYPE"
    echo
    
    read -p "Confirma a instalação com esses parâmetros? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Instalação cancelada pelo usuário."
        exit 0
    fi
}

# Verificar arquivos necessários
check_required_files() {
    header "=== VERIFICANDO ARQUIVOS NECESSÁRIOS ==="
    
    required_files=(
        "tor_router_install.sh"
        "tor_router_advanced_config.sh"
        "setup_monitoring.sh"
        "tor_monitor.py"
        "tor_auto_reconnect.sh"
        "security_checker.py"
        "tor_performance_tester.py"
        "dashboard.html"
    )
    
    missing_files=()
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            missing_files+=("$file")
        else
            info "✓ $file encontrado"
        fi
    done
    
    if [[ ${#missing_files[@]} -gt 0 ]]; then
        error "Arquivos não encontrados: ${missing_files[*]}"
    fi
    
    success "Todos os arquivos necessários estão presentes!"
    echo
}

# Personalizar scripts com parâmetros
customize_scripts() {
    header "=== PERSONALIZANDO SCRIPTS ==="
    
    # Escapar caracteres especiais para sed
    WIFI_SSID_ESC=$(printf '%s\n' "$WIFI_SSID" | sed 's/[[\.*^$()+?{|]/\\&/g')
    WIFI_PASSWORD_ESC=$(printf '%s\n' "$WIFI_PASSWORD" | sed 's/[[\.*^$()+?{|]/\\&/g')
    WIFI_CHANNEL_ESC=$(printf '%s\n' "$WIFI_CHANNEL" | sed 's/[[\.*^$()+?{|]/\\&/g')
    INTERNAL_NETWORK_ESC=$(printf '%s\n' "$INTERNAL_NETWORK" | sed 's/[[\.*^$()+?{|]/\\&/g')
    GATEWAY_IP_ESC=$(printf '%s\n' "$GATEWAY_IP" | sed 's/[[\.*^$()+?{|]/\\&/g')
    INTERNET_INTERFACE_ESC=$(printf '%s\n' "$INTERNET_INTERFACE" | sed 's/[[\.*^$()+?{|]/\\&/g')
    WIFI_INTERFACE_ESC=$(printf '%s\n' "$WIFI_INTERFACE" | sed 's/[[\.*^$()+?{|]/\\&/g')
    LAN_INTERFACE_ESC=$(printf '%s\n' "$LAN_INTERFACE" | sed 's/[[\.*^$()+?{|]/\\&/g')
    
    # Personalizar script de instalação principal usando delimitador |
    sed -i "s|WIFI_SSID=\".*\"|WIFI_SSID=\"$WIFI_SSID_ESC\"|" tor_router_install.sh
    sed -i "s|WIFI_PASSWORD=\".*\"|WIFI_PASSWORD=\"$WIFI_PASSWORD_ESC\"|" tor_router_install.sh
    sed -i "s|WIFI_CHANNEL=\".*\"|WIFI_CHANNEL=\"$WIFI_CHANNEL_ESC\"|" tor_router_install.sh
    sed -i "s|INTERNAL_NETWORK=\".*\"|INTERNAL_NETWORK=\"$INTERNAL_NETWORK_ESC\"|" tor_router_install.sh
    sed -i "s|GATEWAY_IP=\".*\"|GATEWAY_IP=\"$GATEWAY_IP_ESC\"|" tor_router_install.sh
    sed -i "s|INTERNET_INTERFACE=\".*\"|INTERNET_INTERFACE=\"$INTERNET_INTERFACE_ESC\"|" tor_router_install.sh
    sed -i "s|WIFI_INTERFACE=\".*\"|WIFI_INTERFACE=\"$WIFI_INTERFACE_ESC\"|" tor_router_install.sh
    sed -i "s|LAN_INTERFACE=\".*\"|LAN_INTERFACE=\"$LAN_INTERFACE_ESC\"|" tor_router_install.sh
    
    # Personalizar outros scripts conforme necessário
    for script in tor_monitor.py tor_auto_reconnect.sh security_checker.py; do
        if [[ -f "$script" ]]; then
            sed -i "s|'wifi_interface': 'wlan0'|'wifi_interface': '$WIFI_INTERFACE_ESC'|" "$script" 2>/dev/null || true
            sed -i "s|'lan_interface': 'eth1'|'lan_interface': '$LAN_INTERFACE_ESC'|" "$script" 2>/dev/null || true
            sed -i "s|'internet_interface': 'eth0'|'internet_interface': '$INTERNET_INTERFACE_ESC'|" "$script" 2>/dev/null || true
            sed -i "s|'gateway_ip': '192.168.100.1'|'gateway_ip': '$GATEWAY_IP_ESC'|" "$script" 2>/dev/null || true
        fi
    done
    
    success "Scripts personalizados com sucesso!"
    echo
}

# Executar instalação principal
run_main_installation() {
    header "=== EXECUTANDO INSTALAÇÃO PRINCIPAL ==="
    
    log "Iniciando instalação do sistema base..."
    chmod +x tor_router_install.sh
    ./tor_router_install.sh
    
    if [[ $? -eq 0 ]]; then
        success "Instalação principal concluída!"
    else
        error "Falha na instalação principal"
    fi
    echo
}

# Executar configuração avançada
run_advanced_configuration() {
    header "=== EXECUTANDO CONFIGURAÇÃO AVANÇADA ==="
    
    log "Aplicando configurações avançadas..."
    chmod +x tor_router_advanced_config.sh
    ./tor_router_advanced_config.sh
    
    if [[ $? -eq 0 ]]; then
        success "Configuração avançada concluída!"
    else
        error "Falha na configuração avançada"
    fi
    echo
}

# Configurar sistema de monitoramento
setup_monitoring_system() {
    header "=== CONFIGURANDO SISTEMA DE MONITORAMENTO ==="
    
    log "Instalando sistema de monitoramento..."
    chmod +x setup_monitoring.sh
    ./setup_monitoring.sh
    
    if [[ $? -eq 0 ]]; then
        success "Sistema de monitoramento configurado!"
    else
        error "Falha na configuração do monitoramento"
    fi
    echo
}

# Configurar bridges se necessário
configure_bridges() {
    if [[ "$BRIDGE_TYPE" != "none" ]]; then
        header "=== CONFIGURANDO BRIDGES TOR ==="
        
        log "Configurando bridges $BRIDGE_TYPE..."
        /opt/tor_router/configure_bridges.sh "$BRIDGE_TYPE"
        
        if [[ $? -eq 0 ]]; then
            success "Bridges $BRIDGE_TYPE configurados!"
        else
            warning "Falha na configuração de bridges, continuando sem bridges"
        fi
        echo
    fi
}

# Executar testes iniciais
run_initial_tests() {
    header "=== EXECUTANDO TESTES INICIAIS ==="
    
    log "Aguardando inicialização dos serviços..."
    sleep 30
    
    # Testar conectividade TOR
    log "Testando conectividade TOR..."
    if curl --socks5 127.0.0.1:9050 -s https://check.torproject.org/api/ip | grep -q '"IsTor":true'; then
        success "TOR está funcionando corretamente!"
    else
        warning "TOR pode não estar funcionando corretamente"
    fi
    
    # Testar interface web
    log "Testando interface web..."
    if curl -s http://127.0.0.1:8080 > /dev/null; then
        success "Interface web está acessível!"
    else
        warning "Interface web pode não estar funcionando"
    fi
    
    # Testar WiFi
    log "Testando configuração WiFi..."
    if systemctl is-active --quiet hostapd; then
        success "Hostapd está ativo!"
    else
        warning "Hostapd pode não estar funcionando"
    fi
    
    echo
}

# Criar scripts de controle personalizados
create_control_scripts() {
    header "=== CRIANDO SCRIPTS DE CONTROLE ==="
    
    # Script de status personalizado
    cat > /usr/local/bin/tor-router-status << 'EOF'
#!/bin/bash
echo "=== STATUS DO ROTEADOR TOR ==="
echo
echo "Serviços:"
systemctl is-active tor && echo "✓ TOR: Ativo" || echo "✗ TOR: Inativo"
systemctl is-active hostapd && echo "✓ WiFi: Ativo" || echo "✗ WiFi: Inativo"
systemctl is-active dnsmasq && echo "✓ DHCP: Ativo" || echo "✗ DHCP: Inativo"
systemctl is-active tor-monitor && echo "✓ Monitor: Ativo" || echo "✗ Monitor: Inativo"

echo
echo "Conectividade TOR:"
if curl --socks5 127.0.0.1:9050 -s --max-time 10 https://httpbin.org/ip > /dev/null 2>&1; then
    TOR_IP=$(curl --socks5 127.0.0.1:9050 -s --max-time 10 https://httpbin.org/ip | grep -o '"origin":"[^"]*"' | cut -d'"' -f4)
    echo "✓ TOR conectado: $TOR_IP"
else
    echo "✗ TOR não conectado"
fi

echo
echo "Clientes conectados:"
WIFI_CLIENTS=$(iw dev wlan0 station dump 2>/dev/null | grep Station | wc -l)
echo "WiFi: $WIFI_CLIENTS clientes"

echo
echo "Interface web: http://192.168.100.1:8080"
EOF

    chmod +x /usr/local/bin/tor-router-status
    
    # Script de reconexão rápida
    cat > /usr/local/bin/tor-router-reconnect << 'EOF'
#!/bin/bash
echo "Forçando reconexão TOR..."
/opt/tor_router/tor_auto_reconnect.sh manual
echo "Reconexão solicitada!"
EOF

    chmod +x /usr/local/bin/tor-router-reconnect
    
    # Script de reinicialização completa
    cat > /usr/local/bin/tor-router-restart << 'EOF'
#!/bin/bash
echo "Reiniciando roteador TOR..."
systemctl restart tor hostapd dnsmasq tor-monitor
echo "Serviços reiniciados!"
EOF

    chmod +x /usr/local/bin/tor-router-restart
    
    success "Scripts de controle criados!"
    info "Comandos disponíveis:"
    info "  tor-router-status    - Verificar status"
    info "  tor-router-reconnect - Forçar reconexão"
    info "  tor-router-restart   - Reiniciar serviços"
    echo
}

# Configurar inicialização automática
setup_autostart() {
    header "=== CONFIGURANDO INICIALIZAÇÃO AUTOMÁTICA ==="
    
    # Habilitar serviços
    systemctl enable tor
    systemctl enable hostapd
    systemctl enable dnsmasq
    systemctl enable tor-monitor
    
    # Criar script de inicialização
    cat > /etc/systemd/system/tor-router-startup.service << 'EOF'
[Unit]
Description=TOR Router Startup
After=network.target
Wants=tor.service hostapd.service dnsmasq.service

[Service]
Type=oneshot
ExecStart=/opt/tor_router/start_tor_router.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable tor-router-startup.service
    
    success "Inicialização automática configurada!"
    echo
}

# Gerar relatório de instalação
generate_installation_report() {
    header "=== GERANDO RELATÓRIO DE INSTALAÇÃO ==="
    
    REPORT_FILE="/root/tor_router_installation_report.txt"
    
    cat > "$REPORT_FILE" << EOF
RELATÓRIO DE INSTALAÇÃO DO ROTEADOR TOR
=======================================

Data da instalação: $(date)
Sistema operacional: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
Versão do kernel: $(uname -r)

CONFIGURAÇÕES:
- SSID WiFi: $WIFI_SSID
- Canal WiFi: $WIFI_CHANNEL
- Rede interna: $INTERNAL_NETWORK
- Gateway: $GATEWAY_IP
- Interface internet: $INTERNET_INTERFACE
- Interface WiFi: $WIFI_INTERFACE
- Interface LAN: $LAN_INTERFACE
- Bridges TOR: $BRIDGE_TYPE

SERVIÇOS INSTALADOS:
- TOR: $(systemctl is-enabled tor)
- Hostapd: $(systemctl is-enabled hostapd)
- Dnsmasq: $(systemctl is-enabled dnsmasq)
- Monitor TOR: $(systemctl is-enabled tor-monitor)

ARQUIVOS PRINCIPAIS:
- Scripts: /opt/tor_router/
- Configurações: /etc/tor_router/
- Logs: /var/log/tor_router/
- Interface web: http://$GATEWAY_IP:8080

COMANDOS ÚTEIS:
- Status: tor-router-status
- Reconectar: tor-router-reconnect
- Reiniciar: tor-router-restart
- Logs: journalctl -u tor-monitor -f

PRÓXIMOS PASSOS:
1. Reiniciar o sistema: sudo reboot
2. Conectar dispositivos à rede WiFi: $WIFI_SSID
3. Acessar interface web: http://$GATEWAY_IP:8080
4. Verificar status: tor-router-status

DOCUMENTAÇÃO:
- Manual completo: MANUAL_ROTEADOR_TOR.md
- Logs de instalação: /var/log/tor_router/

SUPORTE:
- Verificar logs em caso de problemas
- Executar testes de segurança regularmente
- Manter sistema atualizado

Instalação concluída com sucesso!
EOF

    success "Relatório de instalação gerado: $REPORT_FILE"
    echo
}

# Finalização
finalize_installation() {
    header "=== FINALIZANDO INSTALAÇÃO ==="
    
    # Parar serviços temporariamente para evitar conflitos
    systemctl stop NetworkManager 2>/dev/null || true
    
    # Aplicar configurações finais
    sysctl -p
    
    # Verificar se tudo está funcionando
    if systemctl is-active --quiet tor && systemctl is-active --quiet hostapd; then
        success "Todos os serviços estão ativos!"
    else
        warning "Alguns serviços podem não estar funcionando corretamente"
    fi
    
    echo
    success "🎉 INSTALAÇÃO CONCLUÍDA COM SUCESSO! 🎉"
    echo
    info "Seu roteador TOR está pronto para uso!"
    echo
    echo "PRÓXIMOS PASSOS:"
    echo "1. Reinicie o sistema: sudo reboot"
    echo "2. Conecte-se à rede WiFi: $WIFI_SSID"
    echo "3. Acesse a interface web: http://$GATEWAY_IP:8080"
    echo "4. Verifique o status: tor-router-status"
    echo
    echo "DOCUMENTAÇÃO:"
    echo "- Manual completo: MANUAL_ROTEADOR_TOR.md"
    echo "- Relatório de instalação: /root/tor_router_installation_report.txt"
    echo
    echo "COMANDOS ÚTEIS:"
    echo "- tor-router-status      # Verificar status"
    echo "- tor-router-reconnect   # Forçar reconexão"
    echo "- tor-router-restart     # Reiniciar serviços"
    echo
    
    read -p "Deseja reiniciar o sistema agora? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        log "Reiniciando sistema em 10 segundos..."
        sleep 10
        reboot
    else
        warning "Lembre-se de reiniciar o sistema antes de usar o roteador TOR!"
    fi
}

# Função principal
main() {
    show_banner
    
    log "Iniciando instalação completa do Sistema Roteador TOR..."
    echo
    
    # Executar etapas da instalação
    check_prerequisites
    configure_parameters
    check_required_files
    customize_scripts
    run_main_installation
    run_advanced_configuration
    setup_monitoring_system
    configure_bridges
    create_control_scripts
    setup_autostart
    run_initial_tests
    generate_installation_report
    finalize_installation
}

# Executar instalação
main "$@"

