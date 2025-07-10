#!/bin/bash

# ============================================================================
# SCRIPT DE RECUPERAÇÃO DE EMERGÊNCIA - REDE
# ============================================================================
# Autor: Manus AI
# Data: 2025-07-09
# Versão: 1.0
# Descrição: Recupera conectividade de rede após problemas pós-reboot
# ============================================================================

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função de log
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

# Verificar se é root
if [[ $EUID -ne 0 ]]; then
   error "Este script deve ser executado como root (sudo)"
   exit 1
fi

header "RECUPERAÇÃO DE EMERGÊNCIA - CONECTIVIDADE DE REDE"

log "Iniciando diagnóstico de rede..."

# Parar todos os serviços de rede problemáticos
header "PARANDO SERVIÇOS PROBLEMÁTICOS"
log "Parando serviços que podem estar causando conflitos..."

systemctl stop tor 2>/dev/null || true
systemctl stop hostapd 2>/dev/null || true
systemctl stop dnsmasq 2>/dev/null || true
systemctl stop systemd-networkd 2>/dev/null || true
systemctl stop systemd-resolved 2>/dev/null || true

# Reativar NetworkManager
header "REATIVANDO NETWORKMANAGER"
log "Reabilitando NetworkManager para conectividade básica..."

systemctl unmask NetworkManager 2>/dev/null || true
systemctl enable NetworkManager
systemctl start NetworkManager

# Aguardar NetworkManager inicializar
sleep 5

# Limpar configurações de rede problemáticas
header "LIMPANDO CONFIGURAÇÕES PROBLEMÁTICAS"

log "Removendo configurações de rede que podem estar causando conflitos..."

# Remover configurações systemd-networkd
rm -f /etc/systemd/network/*.network 2>/dev/null || true
rm -f /etc/systemd/network/*.netdev 2>/dev/null || true

# Restaurar configuração padrão do resolved
log "Restaurando configuração padrão do systemd-resolved..."
cat > /etc/systemd/resolved.conf << 'EOF'
[Resolve]
DNS=8.8.8.8 1.1.1.1
FallbackDNS=8.8.4.4 1.0.0.1
#Domains=
#LLMNR=yes
#MulticastDNS=yes
#DNSSEC=yes
#DNSOverTLS=no
#Cache=yes
#DNSStubListener=yes
#ReadEtcHosts=yes
EOF

# Reiniciar resolved
systemctl restart systemd-resolved

# Detectar interfaces de rede
header "DETECTANDO INTERFACES DE REDE"

INTERNET_INTERFACE=""
WIFI_INTERFACE=""

# Detectar interface de internet (ethernet)
for iface in $(ls /sys/class/net/ | grep -E '^(eth|enp|ens)'); do
    if [[ -d "/sys/class/net/$iface" ]]; then
        INTERNET_INTERFACE="$iface"
        log "Interface de internet detectada: $INTERNET_INTERFACE"
        break
    fi
done

# Detectar interface WiFi
for iface in $(ls /sys/class/net/ | grep -E '^(wlan|wlp|wlx)'); do
    if [[ -d "/sys/class/net/$iface" ]]; then
        WIFI_INTERFACE="$iface"
        log "Interface WiFi detectada: $WIFI_INTERFACE"
        break
    fi
done

# Configurar interface de internet
if [[ -n "$INTERNET_INTERFACE" ]]; then
    header "CONFIGURANDO INTERFACE DE INTERNET"
    log "Configurando $INTERNET_INTERFACE para DHCP..."
    
    # Ativar interface
    ip link set "$INTERNET_INTERFACE" up
    
    # Configurar DHCP via NetworkManager
    nmcli connection delete "$INTERNET_INTERFACE" 2>/dev/null || true
    nmcli connection add type ethernet ifname "$INTERNET_INTERFACE" con-name "$INTERNET_INTERFACE"
    nmcli connection modify "$INTERNET_INTERFACE" ipv4.method auto
    nmcli connection up "$INTERNET_INTERFACE"
    
    success "Interface $INTERNET_INTERFACE configurada"
else
    warning "Nenhuma interface de internet detectada"
fi

# Aguardar conectividade
header "TESTANDO CONECTIVIDADE"
log "Aguardando conectividade de rede..."

for i in {1..30}; do
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        success "Conectividade restaurada!"
        break
    fi
    echo -n "."
    sleep 2
done

echo

# Verificar conectividade final
if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    success "Internet funcionando!"
    
    # Mostrar informações de rede
    header "INFORMAÇÕES DE REDE ATUAIS"
    echo "Interfaces ativas:"
    ip addr show | grep -E '^[0-9]+:|inet '
    
    echo
    echo "Rota padrão:"
    ip route show default
    
    echo
    echo "DNS configurado:"
    cat /etc/resolv.conf | grep nameserver
    
else
    error "Ainda sem conectividade. Tentativas adicionais necessárias."
fi

# Criar script de restauração do roteador TOR
header "CRIANDO SCRIPT DE RESTAURAÇÃO DO ROTEADOR TOR"

cat > /opt/restore_tor_router.sh << 'EOF'
#!/bin/bash

# Script para restaurar roteador TOR após recuperação de rede

echo "=== RESTAURANDO ROTEADOR TOR ==="

# Verificar se há internet
if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    echo "ERRO: Sem conectividade de internet. Execute primeiro emergency_network_recovery.sh"
    exit 1
fi

# Reconfigurar interfaces para modo roteador
echo "Reconfigurando interfaces para modo roteador..."

# Parar NetworkManager nas interfaces que serão usadas pelo roteador
nmcli device set wlxc01c30362502 managed no 2>/dev/null || true

# Iniciar serviços do roteador TOR
echo "Iniciando serviços do roteador TOR..."
systemctl start tor
systemctl start hostapd  
systemctl start dnsmasq

# Verificar status
echo "Status dos serviços:"
systemctl is-active tor hostapd dnsmasq

echo "Roteador TOR restaurado!"
EOF

chmod +x /opt/restore_tor_router.sh

success "Script de restauração criado em /opt/restore_tor_router.sh"

header "RECUPERAÇÃO CONCLUÍDA"

echo
success "Rede básica restaurada!"
echo
echo "PRÓXIMOS PASSOS:"
echo "1. Verifique se a internet está funcionando"
echo "2. Se quiser reativar o roteador TOR, execute:"
echo "   sudo /opt/restore_tor_router.sh"
echo
echo "3. Para verificar status da rede:"
echo "   ip addr show"
echo "   ping google.com"
echo

log "Recuperação de emergência concluída!"

