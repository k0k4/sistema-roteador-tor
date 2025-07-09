#!/bin/bash

# ============================================================================
# Script de Configuração do Sistema de Monitoramento TOR
# Sistema: Linux Lite 7.4 / Ubuntu 24.04
# Autor: Manus AI
# Versão: 1.0
# ============================================================================

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

# Verificar se está rodando como root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root (sudo)"
fi

# Diretórios
SCRIPTS_DIR="/opt/tor_router"
CONFIG_DIR="/etc/tor_router"
LOG_DIR="/var/log/tor_router"
DATA_DIR="/opt/tor_router/data"
WEB_DIR="/opt/tor_router/web"

log "Iniciando configuração do sistema de monitoramento..."

# ============================================================================
# CRIAÇÃO DE DIRETÓRIOS
# ============================================================================

log "Criando estrutura de diretórios..."

mkdir -p "$SCRIPTS_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$WEB_DIR/templates"
mkdir -p "$WEB_DIR/static"

# ============================================================================
# INSTALAÇÃO DE DEPENDÊNCIAS PYTHON
# ============================================================================

log "Instalando dependências Python..."

# Atualizar pip
pip3 install --upgrade pip

# Instalar pacotes necessários
pip3 install --upgrade \
    requests \
    psutil \
    netifaces \
    speedtest-cli \
    stem \
    flask \
    schedule \
    sqlite3 \
    bcrypt \
    cryptography \
    pysocks \
    urllib3

# Instalar pacotes adicionais para monitoramento
pip3 install --upgrade \
    matplotlib \
    plotly \
    pandas \
    numpy \
    jinja2 \
    werkzeug

# ============================================================================
# CONFIGURAÇÃO DE ARQUIVOS
# ============================================================================

log "Copiando arquivos de monitoramento..."

# Copiar script principal de monitoramento
if [[ -f "tor_monitor.py" ]]; then
    cp tor_monitor.py "$SCRIPTS_DIR/"
    chmod +x "$SCRIPTS_DIR/tor_monitor.py"
else
    error "Arquivo tor_monitor.py não encontrado"
fi

# Copiar script de reconexão automática
if [[ -f "tor_auto_reconnect.sh" ]]; then
    cp tor_auto_reconnect.sh "$SCRIPTS_DIR/"
    chmod +x "$SCRIPTS_DIR/tor_auto_reconnect.sh"
else
    error "Arquivo tor_auto_reconnect.sh não encontrado"
fi

# Copiar template HTML
if [[ -f "dashboard.html" ]]; then
    cp dashboard.html "$WEB_DIR/templates/"
else
    error "Arquivo dashboard.html não encontrado"
fi

# ============================================================================
# CONFIGURAÇÃO DO SERVIÇO SYSTEMD
# ============================================================================

log "Configurando serviço systemd para monitoramento..."

cat > /etc/systemd/system/tor-monitor.service << 'EOF'
[Unit]
Description=TOR Router Monitor Service
After=network.target tor.service
Wants=tor.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/tor_router
ExecStart=/usr/bin/python3 /opt/tor_router/tor_monitor.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tor-monitor

# Configurações de segurança
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/tor_router /opt/tor_router/data
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes

# Configurações de recursos
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

# ============================================================================
# CONFIGURAÇÃO DO CRON
# ============================================================================

log "Configurando tarefas cron..."

# Criar arquivo de cron para reconexão automática
cat > /etc/cron.d/tor-router << 'EOF'
# Reconexão automática do TOR a cada 30 minutos
*/30 * * * * root /opt/tor_router/tor_auto_reconnect.sh scheduled >> /var/log/tor_router/cron.log 2>&1

# Verificação de conectividade a cada 5 minutos
*/5 * * * * root /opt/tor_router/tor_auto_reconnect.sh connectivity >> /var/log/tor_router/cron.log 2>&1

# Limpeza de logs diária às 2:00
0 2 * * * root /opt/tor_router/cleanup_logs.sh >> /var/log/tor_router/cron.log 2>&1

# Backup de dados semanalmente aos domingos às 3:00
0 3 * * 0 root /opt/tor_router/backup_data.sh >> /var/log/tor_router/cron.log 2>&1

# Verificação de atualizações de bridges mensalmente
0 4 1 * * root /opt/tor_router/update_bridges.sh >> /var/log/tor_router/cron.log 2>&1
EOF

# ============================================================================
# SCRIPTS AUXILIARES
# ============================================================================

log "Criando scripts auxiliares..."

# Script de limpeza de logs
cat > "$SCRIPTS_DIR/cleanup_logs.sh" << 'EOF'
#!/bin/bash

# Script de limpeza de logs

LOG_DIR="/var/log/tor_router"
MAX_SIZE=52428800  # 50MB
MAX_FILES=10

echo "[$(date)] Iniciando limpeza de logs..."

# Função para rotacionar log
rotate_log() {
    local log_file="$1"
    local base_name=$(basename "$log_file")
    
    if [[ -f "$log_file" && $(stat -c%s "$log_file") -gt $MAX_SIZE ]]; then
        echo "Rotacionando $log_file"
        
        # Mover logs antigos
        for i in $(seq $((MAX_FILES - 1)) -1 1); do
            if [[ -f "${log_file}.${i}" ]]; then
                mv "${log_file}.${i}" "${log_file}.$((i + 1))"
            fi
        done
        
        # Comprimir e mover log atual
        gzip -c "$log_file" > "${log_file}.1.gz"
        > "$log_file"  # Limpar arquivo atual
        
        # Remover logs muito antigos
        find "$LOG_DIR" -name "${base_name}.*.gz" -mtime +30 -delete
    fi
}

# Rotacionar logs principais
for log_file in "$LOG_DIR"/*.log; do
    if [[ -f "$log_file" ]]; then
        rotate_log "$log_file"
    fi
done

# Limpar logs temporários
find "$LOG_DIR" -name "*.tmp" -mtime +1 -delete

# Limpar dados antigos do banco
if [[ -f "/opt/tor_router/data/tor_monitor.db" ]]; then
    sqlite3 /opt/tor_router/data/tor_monitor.db "DELETE FROM status_history WHERE timestamp < datetime('now', '-30 days');"
    sqlite3 /opt/tor_router/data/tor_monitor.db "DELETE FROM alerts WHERE timestamp < datetime('now', '-7 days') AND resolved = 1;"
    sqlite3 /opt/tor_router/data/tor_monitor.db "VACUUM;"
fi

echo "[$(date)] Limpeza de logs concluída"
EOF

chmod +x "$SCRIPTS_DIR/cleanup_logs.sh"

# Script de backup
cat > "$SCRIPTS_DIR/backup_data.sh" << 'EOF'
#!/bin/bash

# Script de backup de dados

BACKUP_DIR="/opt/tor_router/backups"
DATA_DIR="/opt/tor_router/data"
CONFIG_DIR="/etc/tor_router"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

echo "[$(date)] Iniciando backup..."

# Criar arquivo de backup
tar -czf "$BACKUP_DIR/tor_router_backup_$DATE.tar.gz" \
    "$DATA_DIR" \
    "$CONFIG_DIR" \
    /etc/tor/torrc \
    /etc/cron.d/tor-router \
    2>/dev/null

# Manter apenas os últimos 10 backups
ls -t "$BACKUP_DIR"/tor_router_backup_*.tar.gz | tail -n +11 | xargs -r rm

echo "[$(date)] Backup concluído: tor_router_backup_$DATE.tar.gz"
EOF

chmod +x "$SCRIPTS_DIR/backup_data.sh"

# Script de atualização de bridges
cat > "$SCRIPTS_DIR/update_bridges.sh" << 'EOF'
#!/bin/bash

# Script de atualização de bridges

CONFIG_DIR="/etc/tor_router"
LOG_FILE="/var/log/tor_router/bridge_update.log"

echo "[$(date)] Atualizando bridges..." >> "$LOG_FILE"

# Função para obter bridges
get_bridges() {
    local bridge_type="$1"
    local output_file="$CONFIG_DIR/bridges_${bridge_type}.txt"
    
    # Tentar obter bridges via API
    curl -s "https://bridges.torproject.org/bridges?transport=$bridge_type" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        | grep -oP 'bridge [^<]+' | head -10 > "$output_file.new" 2>/dev/null
    
    if [[ -s "$output_file.new" ]]; then
        mv "$output_file.new" "$output_file"
        echo "[$(date)] Bridges $bridge_type atualizados" >> "$LOG_FILE"
    else
        rm -f "$output_file.new"
        echo "[$(date)] Falha ao atualizar bridges $bridge_type" >> "$LOG_FILE"
    fi
}

# Atualizar diferentes tipos de bridges
get_bridges "obfs4"
get_bridges "snowflake"

echo "[$(date)] Atualização de bridges concluída" >> "$LOG_FILE"
EOF

chmod +x "$SCRIPTS_DIR/update_bridges.sh"

# ============================================================================
# CONFIGURAÇÃO DE PERMISSÕES
# ============================================================================

log "Configurando permissões..."

# Definir proprietário dos diretórios
chown -R root:root "$SCRIPTS_DIR"
chown -R root:root "$CONFIG_DIR"
chown -R root:root "$LOG_DIR"
chown -R root:root "$DATA_DIR"
chown -R root:root "$WEB_DIR"

# Definir permissões
chmod 755 "$SCRIPTS_DIR"
chmod 755 "$CONFIG_DIR"
chmod 755 "$LOG_DIR"
chmod 755 "$DATA_DIR"
chmod 755 "$WEB_DIR"

# Permissões específicas para scripts
chmod +x "$SCRIPTS_DIR"/*.sh
chmod +x "$SCRIPTS_DIR"/*.py

# Permissões para logs
chmod 644 "$LOG_DIR"/*.log 2>/dev/null || true

# ============================================================================
# CONFIGURAÇÃO DE FIREWALL
# ============================================================================

log "Configurando firewall para interface web..."

# Permitir porta 8080 para interface web (apenas rede interna)
iptables -A INPUT -s 192.168.100.0/24 -p tcp --dport 8080 -j ACCEPT
iptables-save > /etc/iptables/rules.v4

# Configurar UFW também
ufw allow from 192.168.100.0/24 to any port 8080

# ============================================================================
# CONFIGURAÇÃO DE LOGROTATE
# ============================================================================

log "Configurando logrotate..."

cat > /etc/logrotate.d/tor-router << 'EOF'
/var/log/tor_router/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    sharedscripts
    postrotate
        systemctl reload tor-monitor > /dev/null 2>&1 || true
    endscript
}
EOF

# ============================================================================
# CONFIGURAÇÃO DE RSYSLOG
# ============================================================================

log "Configurando rsyslog..."

cat > /etc/rsyslog.d/50-tor-router.conf << 'EOF'
# Logs do TOR Router
:programname, isequal, "tor-monitor" /var/log/tor_router/monitor.log
:programname, isequal, "tor" /var/log/tor_router/tor.log

# Parar processamento para evitar duplicação
:programname, isequal, "tor-monitor" stop
:programname, isequal, "tor" stop
EOF

systemctl restart rsyslog

# ============================================================================
# CONFIGURAÇÃO DE MONITORAMENTO DE SISTEMA
# ============================================================================

log "Configurando monitoramento de sistema..."

# Instalar htop e iftop se não estiverem instalados
apt update -y
apt install -y htop iftop vnstat nload bmon nethogs

# Configurar vnstat para monitoramento de tráfego
vnstat -u -i eth0 2>/dev/null || true
vnstat -u -i wlan0 2>/dev/null || true
vnstat -u -i eth1 2>/dev/null || true

# ============================================================================
# CONFIGURAÇÃO DE ALERTAS
# ============================================================================

log "Configurando sistema de alertas..."

cat > "$SCRIPTS_DIR/send_alert.sh" << 'EOF'
#!/bin/bash

# Script para envio de alertas

ALERT_LEVEL="$1"
ALERT_MESSAGE="$2"
LOG_FILE="/var/log/tor_router/alerts.log"

if [[ -z "$ALERT_LEVEL" || -z "$ALERT_MESSAGE" ]]; then
    echo "Uso: $0 <level> <message>"
    exit 1
fi

# Log do alerta
echo "[$(date)] [$ALERT_LEVEL] $ALERT_MESSAGE" >> "$LOG_FILE"

# Enviar notificação (implementar conforme necessário)
case "$ALERT_LEVEL" in
    "critical")
        # Alertas críticos - implementar notificação urgente
        logger -p user.crit "TOR ROUTER CRITICAL: $ALERT_MESSAGE"
        ;;
    "warning")
        # Alertas de aviso
        logger -p user.warning "TOR ROUTER WARNING: $ALERT_MESSAGE"
        ;;
    "info")
        # Alertas informativos
        logger -p user.info "TOR ROUTER INFO: $ALERT_MESSAGE"
        ;;
esac
EOF

chmod +x "$SCRIPTS_DIR/send_alert.sh"

# ============================================================================
# CONFIGURAÇÃO FINAL
# ============================================================================

log "Aplicando configurações finais..."

# Recarregar daemon do systemd
systemctl daemon-reload

# Habilitar serviço de monitoramento
systemctl enable tor-monitor.service

# Criar arquivo de configuração principal
cat > "$CONFIG_DIR/monitor.conf" << 'EOF'
# Configuração do Monitor TOR Router

# Intervalos (em segundos)
MONITOR_INTERVAL=60
SPEED_TEST_INTERVAL=300
RECONNECT_INTERVAL=1800

# Portas
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051
TOR_DNS_PORT=9053
TOR_TRANS_PORT=9040
WEB_INTERFACE_PORT=8080

# Rede
INTERNAL_NETWORK=192.168.100.0/24
GATEWAY_IP=192.168.100.1

# Interfaces
WIFI_INTERFACE=wlan0
LAN_INTERFACE=eth1
INTERNET_INTERFACE=eth0

# Limites de alerta
CPU_WARNING_THRESHOLD=80
MEMORY_WARNING_THRESHOLD=85
DISK_WARNING_THRESHOLD=90
SPEED_WARNING_THRESHOLD=1.0

# Configurações de log
MAX_LOG_SIZE=10485760
MAX_LOG_FILES=10
LOG_RETENTION_DAYS=30

# Configurações de backup
BACKUP_RETENTION_DAYS=30
BACKUP_INTERVAL_DAYS=7
EOF

# Criar arquivo de status inicial
cat > "$LOG_DIR/system_status.json" << 'EOF'
{
    "installation_date": "$(date -Iseconds)",
    "version": "1.0",
    "status": "installed",
    "components": {
        "monitor": "installed",
        "auto_reconnect": "installed",
        "web_interface": "installed",
        "cron_jobs": "installed",
        "systemd_service": "installed"
    }
}
EOF

# ============================================================================
# VERIFICAÇÃO FINAL
# ============================================================================

log "Executando verificações finais..."

# Verificar se todos os arquivos foram criados
required_files=(
    "$SCRIPTS_DIR/tor_monitor.py"
    "$SCRIPTS_DIR/tor_auto_reconnect.sh"
    "$SCRIPTS_DIR/cleanup_logs.sh"
    "$SCRIPTS_DIR/backup_data.sh"
    "$SCRIPTS_DIR/update_bridges.sh"
    "$SCRIPTS_DIR/send_alert.sh"
    "$WEB_DIR/templates/dashboard.html"
    "$CONFIG_DIR/monitor.conf"
    "/etc/systemd/system/tor-monitor.service"
    "/etc/cron.d/tor-router"
)

missing_files=()
for file in "${required_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        missing_files+=("$file")
    fi
done

if [[ ${#missing_files[@]} -gt 0 ]]; then
    error "Arquivos não encontrados: ${missing_files[*]}"
fi

# Verificar se o serviço pode ser iniciado
if systemctl start tor-monitor.service; then
    success "Serviço de monitoramento iniciado com sucesso"
    systemctl status tor-monitor.service --no-pager
else
    warning "Falha ao iniciar serviço de monitoramento"
fi

# ============================================================================
# FINALIZAÇÃO
# ============================================================================

success "Configuração do sistema de monitoramento concluída!"

echo
echo "=== RESUMO DA INSTALAÇÃO ==="
echo "Diretório principal: $SCRIPTS_DIR"
echo "Diretório de configuração: $CONFIG_DIR"
echo "Diretório de logs: $LOG_DIR"
echo "Interface web: http://192.168.100.1:8080"
echo
echo "=== COMANDOS ÚTEIS ==="
echo "Iniciar monitoramento: systemctl start tor-monitor"
echo "Parar monitoramento: systemctl stop tor-monitor"
echo "Status do monitoramento: systemctl status tor-monitor"
echo "Logs do monitoramento: journalctl -u tor-monitor -f"
echo "Reconexão manual: $SCRIPTS_DIR/tor_auto_reconnect.sh manual"
echo "Limpeza de logs: $SCRIPTS_DIR/cleanup_logs.sh"
echo "Backup de dados: $SCRIPTS_DIR/backup_data.sh"
echo
echo "=== PRÓXIMOS PASSOS ==="
echo "1. Verifique se o TOR está funcionando: systemctl status tor"
echo "2. Acesse a interface web: http://192.168.100.1:8080"
echo "3. Monitore os logs: tail -f $LOG_DIR/monitor.log"
echo "4. Configure alertas conforme necessário"
echo

log "Sistema de monitoramento configurado e pronto para uso!"

