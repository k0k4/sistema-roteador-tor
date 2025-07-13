#!/bin/bash

# ============================================================================
# CORREÇÃO IMEDIATA DOS PROBLEMAS ESPECÍFICOS - ROTEADOR TOR K0K4
# ============================================================================
# Corrige os problemas exatos identificados nas imagens:
# 1. DNSMASQ: Erro "illegal repeated keyword at line 35"
# 2. TOR: Não conectando
# 3. Interfaces: eno1, enp2s0, enp4s0 fora do bridge
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

warning() {
    echo -e "${YELLOW}[AVISO]${NC} $1"
}

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Função para corrigir DNSMASQ (problema linha 35)
fix_dnsmasq_immediate() {
    log "Corrigindo DNSMASQ - Erro linha 35..."
    
    # Parar dnsmasq
    systemctl stop dnsmasq 2>/dev/null || true
    
    # Backup da configuração atual
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    
    # Criar configuração DNSMASQ completamente limpa
    cat > /etc/dnsmasq.conf << 'EOF'
# Configuração DNSMASQ - Roteador TOR K0K4
# Configuração LIMPA sem palavras-chave repetidas

# Configurações básicas
port=53
domain-needed
bogus-priv
no-resolv
no-poll

# Interface específica
interface=br-tor
bind-interfaces

# Configurações DHCP
dhcp-range=192.168.100.10,192.168.100.200,255.255.255.0,12h
dhcp-option=option:router,192.168.100.1
dhcp-option=option:dns-server,192.168.100.1
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

    success "DNSMASQ configurado sem erros"
}

# Função para corrigir TOR
fix_tor_immediate() {
    log "Corrigindo TOR - Problema de conectividade..."
    
    # Parar TOR
    systemctl stop tor 2>/dev/null || true
    
    # Backup da configuração atual
    cp /etc/tor/torrc /etc/tor/torrc.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    
    # Criar configuração TOR limpa e funcional
    cat > /etc/tor/torrc << 'EOF'
# Configuração TOR - Roteador K0K4
# Configuração LIMPA e FUNCIONAL

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

# Configurações para conectividade
ExitPolicy reject *:*
AutomapHostsOnResolve 1
VirtualAddrNetworkIPv4 10.192.0.0/10

# Configurações para melhor conectividade
FascistFirewall 0
ReachableAddresses *:*
ClientOnly 1
SafeLogging 1

# Configurações de performance
NumEntryGuards 3
NewCircuitPeriod 30
MaxCircuitDirtiness 600
CircuitBuildTimeout 60
EOF

    # Limpar dados antigos do TOR
    rm -rf /var/lib/tor/* 2>/dev/null || true
    chown -R debian-tor:debian-tor /var/lib/tor 2>/dev/null || true
    
    success "TOR configurado para conectividade"
}

# Função para corrigir interfaces no bridge
fix_bridge_interfaces() {
    log "Corrigindo interfaces no bridge..."
    
    # Interfaces específicas identificadas nas imagens
    local interfaces=("eno1" "enp2s0" "enp4s0")
    local bridge_name="br-tor"
    
    # Verificar se bridge existe
    if ! ip link show "$bridge_name" >/dev/null 2>&1; then
        log "Criando bridge $bridge_name..."
        ip link add name "$bridge_name" type bridge
        ip link set dev "$bridge_name" up
        ip addr add 192.168.100.1/24 dev "$bridge_name"
        sleep 2
    fi
    
    # Adicionar cada interface ao bridge
    for iface in "${interfaces[@]}"; do
        if [[ -d "/sys/class/net/$iface" ]]; then
            log "Adicionando $iface ao bridge..."
            
            # Preparar interface
            ip link set dev "$iface" down 2>/dev/null || true
            ip addr flush dev "$iface" 2>/dev/null || true
            
            # Remover do NetworkManager
            nmcli device set "$iface" managed no 2>/dev/null || true
            
            # Adicionar ao bridge
            ip link set dev "$iface" up
            if ip link set dev "$iface" master "$bridge_name" 2>/dev/null; then
                success "Interface $iface adicionada ao bridge"
            else
                warning "Falha ao adicionar $iface ao bridge (pode estar sem cabo)"
            fi
        else
            warning "Interface $iface não existe"
        fi
    done
}

# Função para parar serviços conflitantes
stop_conflicting_services() {
    log "Parando serviços conflitantes..."
    
    # Parar systemd-resolved que conflita com dnsmasq
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
    
    # Parar NetworkManager temporariamente nas interfaces LAN
    for iface in eno1 enp2s0 enp4s0; do
        nmcli device set "$iface" managed no 2>/dev/null || true
    done
    
    success "Serviços conflitantes parados"
}

# Função para iniciar serviços na ordem correta
start_services_correct_order() {
    log "Iniciando serviços na ordem correta..."
    
    # Ordem específica para evitar conflitos
    local services=("tor" "dnsmasq" "hostapd")
    
    for service in "${services[@]}"; do
        log "Iniciando $service..."
        
        # Parar primeiro
        systemctl stop "$service" 2>/dev/null || true
        sleep 2
        
        # Iniciar
        if systemctl start "$service" 2>/dev/null; then
            sleep 3
            
            # Verificar se está ativo
            if systemctl is-active "$service" >/dev/null 2>&1; then
                success "$service iniciado com sucesso"
            else
                error "$service falhou na verificação"
                # Mostrar logs para debug
                journalctl -u "$service" --no-pager -n 5
            fi
        else
            error "Falha ao iniciar $service"
            journalctl -u "$service" --no-pager -n 5
        fi
    done
}

# Função para verificar status final
check_final_status() {
    log "Verificando status final..."
    
    echo
    echo -e "${CYAN}=== STATUS FINAL ===${NC}"
    
    # Verificar serviços
    for service in tor hostapd dnsmasq; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            echo -e "  • $service: ${GREEN}ATIVO${NC}"
        else
            echo -e "  • $service: ${RED}INATIVO${NC}"
        fi
    done
    
    # Verificar bridge
    if ip link show br-tor >/dev/null 2>&1; then
        echo -e "  • Bridge: ${GREEN}ATIVO${NC}"
        
        # Verificar interfaces no bridge
        local count=0
        for iface in eno1 enp2s0 enp4s0; do
            if [[ -f "/sys/class/net/$iface/master" ]]; then
                local master=$(cat "/sys/class/net/$iface/master" 2>/dev/null | xargs basename 2>/dev/null || echo "")
                if [[ "$master" == "br-tor" ]]; then
                    echo -e "    • $iface: ${GREEN}NO BRIDGE${NC}"
                    count=$((count + 1))
                else
                    echo -e "    • $iface: ${YELLOW}FORA DO BRIDGE${NC}"
                fi
            else
                echo -e "    • $iface: ${RED}SEM MASTER${NC}"
            fi
        done
        echo -e "    • Total no bridge: $count/3"
    else
        echo -e "  • Bridge: ${RED}INATIVO${NC}"
    fi
    
    # Verificar conectividade TOR (teste rápido)
    echo -e "  • TOR Conectividade: ${YELLOW}Testando...${NC}"
    if timeout 10 curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip >/dev/null 2>&1; then
        echo -e "  • TOR Conectividade: ${GREEN}CONECTADO${NC}"
    else
        echo -e "  • TOR Conectividade: ${YELLOW}NÃO CONECTADO (pode levar alguns minutos)${NC}"
    fi
    
    echo
}

# Função principal
main() {
    echo
    echo -e "${CYAN}============================================================================${NC}"
    echo -e "${CYAN}           CORREÇÃO IMEDIATA DOS PROBLEMAS ESPECÍFICOS${NC}"
    echo -e "${CYAN}============================================================================${NC}"
    echo
    
    # Verificar se é root
    if [[ $EUID -ne 0 ]]; then
        error "Este script deve ser executado como root!"
        exit 1
    fi
    
    info "Corrigindo problemas específicos identificados:"
    info "  1. DNSMASQ: Erro linha 35 (palavra-chave repetida)"
    info "  2. TOR: Não conectando"
    info "  3. Interfaces: eno1, enp2s0, enp4s0 fora do bridge"
    echo
    
    # Executar correções específicas
    stop_conflicting_services
    echo
    
    fix_dnsmasq_immediate
    echo
    
    fix_tor_immediate
    echo
    
    fix_bridge_interfaces
    echo
    
    start_services_correct_order
    echo
    
    check_final_status
    
    echo -e "${CYAN}============================================================================${NC}"
    echo -e "${GREEN}CORREÇÃO IMEDIATA CONCLUÍDA!${NC}"
    echo
    info "Se TOR ainda não conectou, aguarde alguns minutos."
    info "Para verificar novamente: sudo /opt/tor_router/status_tor_router.sh"
    echo -e "${CYAN}============================================================================${NC}"
}

# Executar função principal
main "$@"

