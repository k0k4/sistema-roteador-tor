#!/bin/bash

# ============================================================================
# Script de Reconexão Automática do TOR
# Sistema: Linux Lite 7.4 / Ubuntu 24.04
# Autor: Manus AI
# Versão: 1.0
# 
# Este script é executado automaticamente via cron a cada 30 minutos
# para renovar o circuito TOR e alterar o endereço IP
# ============================================================================

set -e

# Configurações
LOG_FILE="/var/log/tor_router/auto_reconnect.log"
STATUS_FILE="/var/log/tor_router/reconnect_status.json"
TOR_CONTROL_PORT="9051"
TOR_CONTROL_PASSWORD="tor_router_2024"
MAX_RETRIES=3
RETRY_DELAY=10

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Função para log
log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[$timestamp] $message${NC}"
    echo "[$timestamp] $message" >> "$LOG_FILE"
}

error() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[$timestamp] ERRO: $message${NC}" >&2
    echo "[$timestamp] ERRO: $message" >> "$LOG_FILE"
}

warning() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[$timestamp] AVISO: $message${NC}"
    echo "[$timestamp] AVISO: $message" >> "$LOG_FILE"
}

info() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[$timestamp] INFO: $message${NC}"
    echo "[$timestamp] INFO: $message" >> "$LOG_FILE"
}

# Função para verificar se o TOR está rodando
check_tor_running() {
    if systemctl is-active --quiet tor; then
        return 0
    else
        return 1
    fi
}

# Função para verificar conectividade TOR
check_tor_connectivity() {
    local test_url="https://check.torproject.org/api/ip"
    local proxy="socks5://127.0.0.1:9050"
    
    local response=$(curl -s --socks5 "$proxy" --max-time 30 "$test_url" 2>/dev/null)
    
    if echo "$response" | grep -q '"IsTor":true'; then
        return 0
    else
        return 1
    fi
}

# Função para obter IP atual via TOR
get_current_tor_ip() {
    local proxy="socks5://127.0.0.1:9050"
    local ip_services=(
        "https://httpbin.org/ip"
        "https://ipinfo.io/ip"
        "https://api.ipify.org"
        "https://icanhazip.com"
    )
    
    for service in "${ip_services[@]}"; do
        local ip=$(curl -s --socks5 "$proxy" --max-time 15 "$service" 2>/dev/null)
        
        if [[ -n "$ip" ]]; then
            # Extrair IP se for JSON
            if echo "$ip" | grep -q "origin"; then
                ip=$(echo "$ip" | grep -o '"origin":"[^"]*"' | cut -d'"' -f4 | cut -d',' -f1)
            fi
            
            # Validar formato IP
            if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                echo "$ip"
                return 0
            fi
        fi
    done
    
    return 1
}

# Função para reconectar TOR via controle
reconnect_tor_control() {
    local retries=0
    
    while [[ $retries -lt $MAX_RETRIES ]]; do
        info "Tentativa de reconexão $((retries + 1))/$MAX_RETRIES"
        
        # Usar telnet para enviar comando NEWNYM
        {
            echo "AUTHENTICATE \"$TOR_CONTROL_PASSWORD\""
            sleep 1
            echo "SIGNAL NEWNYM"
            sleep 1
            echo "QUIT"
        } | telnet 127.0.0.1 "$TOR_CONTROL_PORT" >/dev/null 2>&1
        
        if [[ $? -eq 0 ]]; then
            info "Comando NEWNYM enviado com sucesso"
            sleep 5  # Aguardar estabelecimento do novo circuito
            return 0
        else
            warning "Falha ao enviar comando NEWNYM (tentativa $((retries + 1)))"
            retries=$((retries + 1))
            sleep $RETRY_DELAY
        fi
    done
    
    return 1
}

# Função para reconectar via reinicialização do serviço
reconnect_tor_service() {
    info "Reiniciando serviço TOR..."
    
    systemctl restart tor
    
    if [[ $? -eq 0 ]]; then
        info "Serviço TOR reiniciado com sucesso"
        
        # Aguardar inicialização
        local wait_time=0
        local max_wait=60
        
        while [[ $wait_time -lt $max_wait ]]; do
            if check_tor_running && check_tor_connectivity; then
                info "TOR reconectado após $wait_time segundos"
                return 0
            fi
            
            sleep 5
            wait_time=$((wait_time + 5))
        done
        
        error "TOR não conseguiu reconectar após reinicialização"
        return 1
    else
        error "Falha ao reiniciar serviço TOR"
        return 1
    fi
}

# Função para verificar vazamentos DNS
check_dns_leaks() {
    local proxy="socks5://127.0.0.1:9050"
    local dns_test_url="https://www.dnsleaktest.com/results.json"
    
    local response=$(curl -s --socks5 "$proxy" --max-time 30 "$dns_test_url" 2>/dev/null)
    
    if [[ -n "$response" ]]; then
        # Verificar se há servidores DNS suspeitos
        local suspicious_ranges=("192.168." "10." "172.16." "172.17." "172.18." "172.19." "172.20." "172.21." "172.22." "172.23." "172.24." "172.25." "172.26." "172.27." "172.28." "172.29." "172.30." "172.31." "127." "169.254.")
        
        for range in "${suspicious_ranges[@]}"; do
            if echo "$response" | grep -q "$range"; then
                warning "Possível vazamento DNS detectado: $range"
                return 1
            fi
        done
        
        info "Verificação DNS: OK"
        return 0
    else
        warning "Não foi possível verificar vazamentos DNS"
        return 1
    fi
}

# Função para verificar velocidade básica
check_basic_speed() {
    local proxy="socks5://127.0.0.1:9050"
    local test_url="https://httpbin.org/bytes/1048576"  # 1MB
    
    local start_time=$(date +%s.%N)
    local response=$(curl -s --socks5 "$proxy" --max-time 60 "$test_url" 2>/dev/null)
    local end_time=$(date +%s.%N)
    
    if [[ -n "$response" ]]; then
        local duration=$(echo "$end_time - $start_time" | bc)
        local speed_mbps=$(echo "scale=2; 8 / $duration" | bc)  # 8 Mbits / duration
        
        info "Velocidade estimada: ${speed_mbps} Mbps"
        
        # Verificar se a velocidade é muito baixa
        if (( $(echo "$speed_mbps < 0.5" | bc -l) )); then
            warning "Velocidade muito baixa: ${speed_mbps} Mbps"
            return 1
        fi
        
        return 0
    else
        warning "Falha no teste de velocidade"
        return 1
    fi
}

# Função para salvar status da reconexão
save_reconnect_status() {
    local old_ip="$1"
    local new_ip="$2"
    local success="$3"
    local method="$4"
    local reason="$5"
    
    cat > "$STATUS_FILE" << EOF
{
    "timestamp": "$(date -Iseconds)",
    "old_ip": "$old_ip",
    "new_ip": "$new_ip",
    "success": $success,
    "method": "$method",
    "reason": "$reason",
    "dns_check": $(check_dns_leaks && echo "true" || echo "false"),
    "speed_check": $(check_basic_speed && echo "true" || echo "false")
}
EOF
}

# Função para verificar se é necessário reconectar
should_reconnect() {
    local reason="$1"
    
    case "$reason" in
        "scheduled")
            # Reconexão agendada - sempre executar
            return 0
            ;;
        "connectivity")
            # Problema de conectividade - sempre executar
            return 0
            ;;
        "speed")
            # Velocidade baixa - verificar se persistente
            if ! check_basic_speed; then
                return 0
            fi
            return 1
            ;;
        "dns_leak")
            # Vazamento DNS - sempre executar
            return 0
            ;;
        *)
            # Motivo desconhecido - executar por segurança
            return 0
            ;;
    esac
}

# Função principal de reconexão
main_reconnect() {
    local reason="${1:-scheduled}"
    
    log "Iniciando processo de reconexão automática - Motivo: $reason"
    
    # Verificar se o TOR está rodando
    if ! check_tor_running; then
        error "Serviço TOR não está rodando"
        systemctl start tor
        sleep 10
        
        if ! check_tor_running; then
            error "Falha ao iniciar serviço TOR"
            save_reconnect_status "unknown" "unknown" false "service_start" "$reason"
            exit 1
        fi
    fi
    
    # Verificar se é necessário reconectar
    if ! should_reconnect "$reason"; then
        info "Reconexão não necessária no momento"
        exit 0
    fi
    
    # Obter IP atual
    local old_ip=$(get_current_tor_ip)
    if [[ -z "$old_ip" ]]; then
        warning "Não foi possível obter IP atual"
        old_ip="unknown"
    else
        info "IP atual: $old_ip"
    fi
    
    # Tentar reconexão via controle primeiro
    local reconnect_success=false
    local method="control"
    
    if reconnect_tor_control; then
        info "Reconexão via controle bem-sucedida"
        reconnect_success=true
    else
        warning "Reconexão via controle falhou, tentando reinicialização do serviço"
        method="service_restart"
        
        if reconnect_tor_service; then
            info "Reconexão via reinicialização bem-sucedida"
            reconnect_success=true
        else
            error "Todas as tentativas de reconexão falharam"
        fi
    fi
    
    # Verificar novo IP
    local new_ip="unknown"
    if [[ "$reconnect_success" == true ]]; then
        sleep 10  # Aguardar estabilização
        
        new_ip=$(get_current_tor_ip)
        if [[ -n "$new_ip" && "$new_ip" != "$old_ip" ]]; then
            log "Reconexão bem-sucedida: $old_ip -> $new_ip"
        else
            warning "IP não mudou após reconexão: $old_ip -> $new_ip"
            reconnect_success=false
        fi
    fi
    
    # Verificar conectividade final
    if [[ "$reconnect_success" == true ]]; then
        if check_tor_connectivity; then
            info "Verificação de conectividade: OK"
        else
            warning "Falha na verificação de conectividade"
            reconnect_success=false
        fi
    fi
    
    # Salvar status
    save_reconnect_status "$old_ip" "$new_ip" "$reconnect_success" "$method" "$reason"
    
    # Verificações adicionais
    check_dns_leaks
    check_basic_speed
    
    if [[ "$reconnect_success" == true ]]; then
        log "Processo de reconexão concluído com sucesso"
        exit 0
    else
        error "Processo de reconexão falhou"
        exit 1
    fi
}

# Função para limpeza de logs antigos
cleanup_logs() {
    local log_dir="/var/log/tor_router"
    local max_size=10485760  # 10MB
    
    if [[ -f "$LOG_FILE" && $(stat -c%s "$LOG_FILE") -gt $max_size ]]; then
        info "Rotacionando log de reconexão"
        
        # Manter últimas 1000 linhas
        tail -n 1000 "$LOG_FILE" > "${LOG_FILE}.tmp"
        mv "${LOG_FILE}.tmp" "$LOG_FILE"
    fi
}

# Verificar se está rodando como root
if [[ $EUID -ne 0 ]]; then
    error "Este script deve ser executado como root"
    exit 1
fi

# Criar diretório de log se não existir
mkdir -p "$(dirname "$LOG_FILE")"

# Limpeza de logs
cleanup_logs

# Verificar argumentos
REASON="${1:-scheduled}"

# Executar reconexão principal
main_reconnect "$REASON"

