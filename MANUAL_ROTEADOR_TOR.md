# Manual Completo do Roteador TOR
## Sistema de Roteador TOR para Linux Lite 7.4 / Ubuntu 24.04

**Versão:** 1.0  
**Autor:** Manus AI  
**Data:** Janeiro 2025  

---

## Índice

1. [Introdução](#introdução)
2. [Requisitos do Sistema](#requisitos-do-sistema)
3. [Instalação](#instalação)
4. [Configuração](#configuração)
5. [Monitoramento](#monitoramento)
6. [Segurança](#segurança)
7. [Solução de Problemas](#solução-de-problemas)
8. [Manutenção](#manutenção)
9. [Referências](#referências)

---

## Introdução

Este sistema transforma seu computador Linux Lite 7.4 em um roteador TOR completo, proporcionando anonimato e privacidade para toda sua rede doméstica. O sistema inclui:

### Características Principais

- **Roteamento TOR Transparente**: Todo o tráfego da rede é automaticamente roteado através da rede TOR
- **Hotspot WiFi Seguro**: Cria um ponto de acesso WiFi protegido com WPA2
- **Reconexão Automática**: Muda o endereço IP a cada 30 minutos automaticamente
- **Monitoramento em Tempo Real**: Interface web para monitoramento completo do sistema
- **Verificação de Segurança**: Detecção automática de vazamentos DNS, IP e WebRTC
- **Teste de Performance**: Análise detalhada de velocidade e latência
- **Sistema de Alertas**: Notificações automáticas de problemas de segurança
- **Backup Automático**: Backup regular de configurações e dados

### Arquitetura do Sistema

```
Internet ←→ [Interface Externa] ←→ [TOR] ←→ [Roteador] ←→ [WiFi/LAN] ←→ Dispositivos
```

O sistema funciona interceptando todo o tráfego da rede interna e redirecionando-o através da rede TOR, garantindo anonimato completo para todos os dispositivos conectados.

---

## Requisitos do Sistema

### Hardware Mínimo

- **Processador**: Intel/AMD x64 de 2 núcleos ou superior
- **Memória RAM**: 4GB mínimo, 8GB recomendado
- **Armazenamento**: 20GB de espaço livre
- **Interfaces de Rede**: 
  - 1x Interface Ethernet para internet (eth0)
  - 1x Interface Ethernet para LAN (eth1) - opcional
  - 1x Interface WiFi para hotspot (wlan0)

### Software

- **Sistema Operacional**: Linux Lite 7.4 ou Ubuntu 24.04 LTS
- **Privilégios**: Acesso root (sudo)
- **Conexão**: Internet ativa durante a instalação

### Interfaces de Rede Recomendadas

| Interface | Função | Descrição |
|-----------|--------|-----------|
| eth0 | Internet | Conexão com a internet |
| eth1 | LAN | Rede cabeada interna (opcional) |
| wlan0 | WiFi | Hotspot para dispositivos móveis |

---

## Instalação

### Passo 1: Preparação do Sistema

Primeiro, certifique-se de que o sistema está atualizado:

```bash
sudo apt update && sudo apt upgrade -y
```

### Passo 2: Download dos Scripts

Baixe todos os scripts do sistema:

```bash
# Criar diretório de trabalho
mkdir -p ~/tor_router_setup
cd ~/tor_router_setup

# Os scripts devem estar no diretório atual:
# - tor_router_install.sh
# - tor_router_advanced_config.sh
# - setup_monitoring.sh
# - tor_monitor.py
# - tor_auto_reconnect.sh
# - security_checker.py
# - tor_performance_tester.py
# - dashboard.html
```

### Passo 3: Instalação Principal

Execute o script de instalação principal:

```bash
sudo chmod +x tor_router_install.sh
sudo ./tor_router_install.sh
```

Este script irá:
- Instalar todos os pacotes necessários
- Configurar o TOR
- Configurar hostapd para WiFi
- Configurar dnsmasq para DHCP
- Configurar iptables para roteamento
- Criar scripts de controle

### Passo 4: Configuração Avançada

Execute a configuração avançada:

```bash
sudo chmod +x tor_router_advanced_config.sh
sudo ./tor_router_advanced_config.sh
```

### Passo 5: Sistema de Monitoramento

Configure o sistema de monitoramento:

```bash
sudo chmod +x setup_monitoring.sh
sudo ./setup_monitoring.sh
```

### Passo 6: Reinicialização

Reinicie o sistema para aplicar todas as configurações:

```bash
sudo reboot
```

### Passo 7: Verificação da Instalação

Após a reinicialização, verifique se tudo está funcionando:

```bash
# Verificar status dos serviços
sudo systemctl status tor
sudo systemctl status hostapd
sudo systemctl status dnsmasq
sudo systemctl status tor-monitor

# Verificar status do roteador
sudo /opt/tor_router/status_tor_router.sh
```

---

## Configuração

### Configuração de Rede

#### Configurações Padrão

| Parâmetro | Valor Padrão | Descrição |
|-----------|--------------|-----------|
| SSID WiFi | TOR_Router_Secure | Nome da rede WiFi |
| Senha WiFi | TorSecure2024! | Senha da rede WiFi |
| Gateway IP | 192.168.100.1 | IP do roteador |
| Rede Interna | 192.168.100.0/24 | Faixa de IPs internos |
| DHCP Range | 192.168.100.10-200 | Faixa de IPs para clientes |

#### Personalização da Rede WiFi

Para alterar as configurações WiFi, edite o arquivo:

```bash
sudo nano /etc/hostapd/hostapd.conf
```

Principais parâmetros:
```
ssid=SEU_NOME_WIFI
wpa_passphrase=SUA_SENHA_WIFI
channel=6
```

Após alterar, reinicie o hostapd:
```bash
sudo systemctl restart hostapd
```

#### Configuração de Bridges TOR

Para usar bridges (recomendado em países com censura):

```bash
# Configurar bridges obfs4
sudo /opt/tor_router/configure_bridges.sh obfs4

# Configurar bridges snowflake
sudo /opt/tor_router/configure_bridges.sh snowflake

# Desabilitar bridges
sudo /opt/tor_router/configure_bridges.sh none
```

### Configuração de Segurança

#### Configurações de País

O sistema está configurado para evitar países com censura. Para personalizar:

```bash
sudo nano /etc/tor/torrc
```

Edite as linhas:
```
ExitNodes {us},{ca},{de},{nl},{se},{ch},{no},{dk},{fi}
EntryNodes {us},{ca},{de},{nl},{se},{ch},{no},{dk},{fi}
```

#### Configurações de Firewall

O sistema inclui firewall avançado. Para personalizar:

```bash
sudo /opt/tor_router/setup_advanced_firewall.sh
```

### Configuração de Monitoramento

#### Interface Web

A interface web está disponível em:
- **URL**: http://192.168.100.1:8080
- **Acesso**: Apenas da rede interna

#### Configuração de Alertas

Edite as configurações de monitoramento:

```bash
sudo nano /etc/tor_router/monitor.conf
```

Principais parâmetros:
```
MONITOR_INTERVAL=60
SPEED_TEST_INTERVAL=300
RECONNECT_INTERVAL=1800
CPU_WARNING_THRESHOLD=80
MEMORY_WARNING_THRESHOLD=85
```

---

## Monitoramento

### Interface Web

A interface web fornece monitoramento em tempo real de:

#### Dashboard Principal
- Status da conexão TOR
- IP atual e localização
- Velocidade de download/upload
- Latência da conexão
- Clientes conectados
- Recursos do sistema (CPU, memória, disco)

#### Verificações de Segurança
- Vazamentos DNS
- Vazamentos IP
- Vazamentos WebRTC
- Consistência de geolocalização

#### Estatísticas
- Histórico de reconexões
- Testes de velocidade
- Tempo de atividade
- Dados transferidos

### Comandos de Monitoramento

#### Status Geral
```bash
# Status completo do sistema
sudo /opt/tor_router/status_tor_router.sh

# Status dos serviços
sudo systemctl status tor hostapd dnsmasq tor-monitor

# Logs em tempo real
sudo journalctl -u tor-monitor -f
```

#### Verificação de Segurança
```bash
# Verificação completa de segurança
sudo python3 /opt/tor_router/security_checker.py

# Teste de performance
sudo python3 /opt/tor_router/tor_performance_tester.py

# Monitoramento de rede
sudo /opt/tor_router/network_monitor.sh
```

#### Logs do Sistema
```bash
# Logs do TOR
sudo tail -f /var/log/tor/tor.log

# Logs do monitoramento
sudo tail -f /var/log/tor_router/monitor.log

# Logs de reconexão
sudo tail -f /var/log/tor_router/auto_reconnect.log

# Logs de segurança
sudo tail -f /var/log/tor_router/security_checker.log
```

### Alertas Automáticos

O sistema gera alertas automáticos para:

#### Alertas Críticos
- TOR desconectado
- Vazamentos de IP detectados
- Falha total do sistema

#### Alertas de Aviso
- Vazamentos DNS
- Velocidade muito baixa
- Uso alto de recursos
- Problemas de conectividade

#### Alertas Informativos
- Reconexão bem-sucedida
- Teste de velocidade concluído
- Backup realizado

---

## Segurança

### Verificações Automáticas

O sistema realiza verificações automáticas de segurança:

#### Verificação de Vazamentos
- **DNS Leaks**: Verifica se consultas DNS estão vazando
- **IP Leaks**: Detecta vazamentos de IP real
- **WebRTC Leaks**: Identifica vazamentos via WebRTC

#### Verificação de Anonimato
- **Geolocalização**: Verifica consistência de localização
- **Fingerprinting**: Testa resistência a fingerprinting
- **Headers HTTP**: Analisa headers suspeitos

### Configurações de Segurança Avançada

#### Hardening do Sistema
```bash
# Aplicar configurações de segurança
sudo /opt/tor_router/optimize_performance.sh

# Configurar firewall avançado
sudo /opt/tor_router/setup_advanced_firewall.sh
```

#### Configurações de Privacidade
```bash
# Editar configurações TOR
sudo nano /etc/tor/torrc

# Configurações recomendadas para máxima privacidade:
SafeLogging 1
AvoidDiskWrites 1
DisableAllSwap 1
HardwareAccel 1
```

### Melhores Práticas

#### Para Usuários
1. **Sempre use HTTPS** quando possível
2. **Desabilite JavaScript** em navegadores para máxima segurança
3. **Use Tor Browser** em vez de navegadores comuns
4. **Não faça login** em contas pessoais
5. **Evite downloads** de arquivos grandes

#### Para Administradores
1. **Monitore logs** regularmente
2. **Atualize bridges** mensalmente
3. **Faça backup** das configurações
4. **Teste segurança** semanalmente
5. **Monitore performance** continuamente

---

## Solução de Problemas

### Problemas Comuns

#### TOR Não Conecta

**Sintomas:**
- Interface web mostra "TOR desconectado"
- Não há acesso à internet nos dispositivos

**Soluções:**
```bash
# Verificar status do TOR
sudo systemctl status tor

# Reiniciar TOR
sudo systemctl restart tor

# Verificar logs
sudo tail -f /var/log/tor/tor.log

# Testar conectividade
curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip
```

#### WiFi Não Funciona

**Sintomas:**
- Rede WiFi não aparece
- Não consegue conectar ao WiFi

**Soluções:**
```bash
# Verificar hostapd
sudo systemctl status hostapd

# Verificar interface WiFi
ip addr show wlan0

# Reiniciar hostapd
sudo systemctl restart hostapd

# Verificar configuração
sudo nano /etc/hostapd/hostapd.conf
```

#### Velocidade Muito Baixa

**Sintomas:**
- Navegação muito lenta
- Timeouts frequentes

**Soluções:**
```bash
# Testar velocidade
sudo python3 /opt/tor_router/tor_performance_tester.py

# Trocar circuito
sudo /opt/tor_router/tor_auto_reconnect.sh manual

# Configurar bridges
sudo /opt/tor_router/configure_bridges.sh obfs4

# Otimizar performance
sudo /opt/tor_router/optimize_performance.sh
```

#### Vazamentos Detectados

**Sintomas:**
- Alertas de vazamento na interface web
- IP real sendo detectado

**Soluções:**
```bash
# Verificar segurança
sudo python3 /opt/tor_router/security_checker.py

# Reconfigurar firewall
sudo /opt/tor_router/setup_advanced_firewall.sh

# Verificar DNS
sudo nano /etc/dnsmasq.conf

# Reiniciar serviços
sudo systemctl restart tor dnsmasq
```

### Logs de Diagnóstico

#### Coleta de Logs
```bash
# Script para coletar todos os logs
sudo /opt/tor_router/collect_diagnostic_logs.sh
```

#### Análise de Logs
```bash
# Verificar erros no TOR
sudo grep -i error /var/log/tor/tor.log

# Verificar problemas de rede
sudo grep -i "connection failed" /var/log/tor_router/monitor.log

# Verificar alertas de segurança
sudo grep -i "alert" /var/log/tor_router/security_checker.log
```

### Recuperação do Sistema

#### Backup e Restauração
```bash
# Fazer backup manual
sudo /opt/tor_router/backup_data.sh

# Restaurar configuração
sudo tar -xzf /opt/tor_router/backups/tor_router_backup_YYYYMMDD_HHMMSS.tar.gz -C /
```

#### Reset Completo
```bash
# Parar todos os serviços
sudo /opt/tor_router/stop_tor_router.sh

# Limpar configurações
sudo rm -rf /etc/tor_router/*

# Reinstalar
sudo ./tor_router_install.sh
```

---

## Manutenção

### Manutenção Automática

O sistema inclui tarefas automáticas de manutenção:

#### Tarefas Diárias
- Limpeza de logs antigos
- Verificação de segurança
- Monitoramento de recursos

#### Tarefas Semanais
- Backup de configurações
- Teste de performance
- Atualização de estatísticas

#### Tarefas Mensais
- Atualização de bridges
- Limpeza de dados antigos
- Verificação de atualizações

### Manutenção Manual

#### Limpeza do Sistema
```bash
# Limpar logs
sudo /opt/tor_router/cleanup_logs.sh

# Limpar cache
sudo apt autoclean
sudo apt autoremove

# Verificar espaço em disco
df -h
```

#### Atualização do Sistema
```bash
# Atualizar pacotes
sudo apt update && sudo apt upgrade

# Atualizar bridges
sudo /opt/tor_router/update_bridges.sh

# Verificar atualizações TOR
sudo apt list --upgradable | grep tor
```

#### Otimização de Performance
```bash
# Otimizar sistema
sudo /opt/tor_router/optimize_performance.sh

# Analisar gargalos
sudo python3 /opt/tor_router/tor_performance_tester.py

# Ajustar configurações
sudo nano /etc/tor_router/monitor.conf
```

### Monitoramento de Saúde

#### Verificações Regulares
```bash
# Status geral (executar diariamente)
sudo /opt/tor_router/status_tor_router.sh

# Verificação de segurança (executar semanalmente)
sudo python3 /opt/tor_router/security_checker.py

# Teste de performance (executar mensalmente)
sudo python3 /opt/tor_router/tor_performance_tester.py
```

#### Métricas Importantes
- **Uptime**: Deve ser > 99%
- **Velocidade**: Deve ser > 1 Mbps
- **Latência**: Deve ser < 2000ms
- **Vazamentos**: Deve ser 0
- **Reconexões**: Deve ser automática a cada 30min

---

## Referências

### Documentação Oficial
- [Tor Project](https://www.torproject.org/)
- [Tor Manual](https://2019.www.torproject.org/docs/tor-manual.html.en)
- [Ubuntu Documentation](https://help.ubuntu.com/)

### Ferramentas de Segurança
- [DNS Leak Test](https://www.dnsleaktest.com/)
- [IP Leak Test](https://ipleak.net/)
- [Browser Leaks](https://browserleaks.com/)

### Configuração de Rede
- [Hostapd Documentation](https://w1.fi/hostapd/)
- [Dnsmasq Manual](http://www.thekelleys.org.uk/dnsmasq/doc.html)
- [Iptables Tutorial](https://www.netfilter.org/documentation/HOWTO/packet-filtering-HOWTO.html)

### Bridges TOR
- [Tor Bridges](https://bridges.torproject.org/)
- [Pluggable Transports](https://tb-manual.torproject.org/circumvention/)

---

## Apêndices

### Apêndice A: Estrutura de Arquivos

```
/opt/tor_router/
├── tor_monitor.py              # Monitor principal
├── tor_auto_reconnect.sh       # Reconexão automática
├── security_checker.py         # Verificador de segurança
├── tor_performance_tester.py   # Testador de performance
├── setup_iptables.sh          # Configuração de firewall
├── configure_bridges.sh        # Configuração de bridges
├── optimize_performance.sh     # Otimização de sistema
├── cleanup_logs.sh            # Limpeza de logs
├── backup_data.sh             # Backup de dados
├── update_bridges.sh          # Atualização de bridges
├── start_tor_router.sh        # Iniciar roteador
├── stop_tor_router.sh         # Parar roteador
├── status_tor_router.sh       # Status do roteador
├── data/                      # Dados do sistema
│   ├── tor_monitor.db         # Banco de dados
│   └── security_checks.db     # Dados de segurança
├── web/                       # Interface web
│   └── templates/
│       └── dashboard.html     # Dashboard principal
└── backups/                   # Backups automáticos
```

### Apêndice B: Portas Utilizadas

| Porta | Serviço | Descrição |
|-------|---------|-----------|
| 9050 | TOR SOCKS | Proxy SOCKS5 |
| 9051 | TOR Control | Controle do TOR |
| 9053 | TOR DNS | Proxy DNS |
| 9040 | TOR Trans | Proxy transparente |
| 8080 | Web Interface | Interface de monitoramento |
| 53 | DNS | Servidor DNS interno |
| 67/68 | DHCP | Servidor DHCP |

### Apêndice C: Comandos Úteis

```bash
# Verificar IP TOR atual
curl --socks5 127.0.0.1:9050 https://httpbin.org/ip

# Forçar nova identidade TOR
echo -e 'AUTHENTICATE "tor_router_2024"\r\nSIGNAL NEWNYM\r\nQUIT' | nc 127.0.0.1 9051

# Verificar clientes conectados
iw dev wlan0 station dump | grep Station | wc -l

# Monitorar tráfego
sudo iftop -i wlan0

# Verificar uso de recursos
htop

# Testar vazamentos DNS
dig @127.0.0.1 -p 9053 google.com

# Verificar regras iptables
sudo iptables -L -n -v
```

---

**Fim do Manual**

Para suporte adicional ou dúvidas, consulte os logs do sistema ou execute os scripts de diagnóstico incluídos no pacote.

