# 🛡️ Sistema Roteador TOR Completo

**Transforme seu computador Linux em um roteador TOR seguro para toda sua casa!**

## 🚀 Instalação Rápida

### Pré-requisitos
- Linux Lite 7.4 ou Ubuntu 24.04 LTS
- Acesso root (sudo)
- Conexão com internet
- Adaptador WiFi compatível

### Instalação Automática (Recomendado)

```bash
# 1. Baixar todos os arquivos para um diretório
mkdir ~/tor_router && cd ~/tor_router

# 2. Executar instalação completa
sudo chmod +x install_complete_system.sh
sudo ./install_complete_system.sh
```

### Instalação Manual

```bash
# 1. Instalação base
sudo chmod +x tor_router_install.sh
sudo ./tor_router_install.sh

# 2. Configuração avançada
sudo chmod +x tor_router_advanced_config.sh
sudo ./tor_router_advanced_config.sh

# 3. Sistema de monitoramento
sudo chmod +x setup_monitoring.sh
sudo ./setup_monitoring.sh

# 4. Reiniciar sistema
sudo reboot
```

## 📋 Arquivos Incluídos

| Arquivo | Descrição |
|---------|-----------|
| `install_complete_system.sh` | **Instalação automática completa** |
| `tor_router_install.sh` | Instalação base do sistema |
| `tor_router_advanced_config.sh` | Configurações avançadas |
| `setup_monitoring.sh` | Sistema de monitoramento |
| `tor_monitor.py` | Monitor principal em Python |
| `tor_auto_reconnect.sh` | Reconexão automática a cada 30min |
| `security_checker.py` | Verificador de vazamentos e segurança |
| `tor_performance_tester.py` | Testador de performance |
| `dashboard.html` | Interface web de monitoramento |
| `MANUAL_ROTEADOR_TOR.md` | **Manual completo detalhado** |

## ⚡ Configurações Padrão

| Parâmetro | Valor Padrão |
|-----------|--------------|
| **SSID WiFi** | `TOR_Router_Secure` |
| **Senha WiFi** | `TorSecure2024!` |
| **Gateway IP** | `192.168.100.1` |
| **Rede Interna** | `192.168.100.0/24` |
| **Interface Web** | `http://192.168.100.1:8080` |
| **Reconexão** | A cada 30 minutos |

## 🎯 Funcionalidades

### ✅ Roteamento TOR
- Todo tráfego roteado através da rede TOR
- Mudança automática de IP a cada 30 minutos
- Suporte a bridges para países com censura
- Configuração transparente para todos os dispositivos

### ✅ Hotspot WiFi Seguro
- Rede WiFi protegida com WPA2
- Suporte para múltiplos dispositivos
- Configuração automática de DHCP
- Isolamento de rede para segurança

### ✅ Monitoramento Completo
- Interface web em tempo real
- Verificação automática de vazamentos
- Testes de velocidade e latência
- Sistema de alertas inteligente
- Histórico de conexões e estatísticas

### ✅ Segurança Avançada
- Detecção de vazamentos DNS/IP/WebRTC
- Firewall configurado automaticamente
- Verificação de fingerprinting
- Análise de geolocalização
- Logs detalhados de segurança

## 🖥️ Interface Web

Acesse `http://192.168.100.1:8080` para:

- **Dashboard**: Status em tempo real
- **Segurança**: Verificações de vazamentos
- **Performance**: Testes de velocidade
- **Estatísticas**: Histórico e métricas
- **Controles**: Reconexão manual e configurações

## 📱 Comandos Úteis

```bash
# Verificar status geral
tor-router-status

# Forçar reconexão TOR
tor-router-reconnect

# Reiniciar todos os serviços
tor-router-restart

# Verificar logs em tempo real
sudo journalctl -u tor-monitor -f

# Teste de segurança completo
sudo python3 /opt/tor_router/security_checker.py

# Teste de performance
sudo python3 /opt/tor_router/tor_performance_tester.py
```

## 🔧 Configuração Personalizada

### Alterar Configurações WiFi
```bash
sudo nano /etc/hostapd/hostapd.conf
sudo systemctl restart hostapd
```

### Configurar Bridges TOR
```bash
# Bridges obfs4 (recomendado para censura)
sudo /opt/tor_router/configure_bridges.sh obfs4

# Bridges snowflake (alternativa)
sudo /opt/tor_router/configure_bridges.sh snowflake

# Desabilitar bridges
sudo /opt/tor_router/configure_bridges.sh none
```

### Otimizar Performance
```bash
sudo /opt/tor_router/optimize_performance.sh
```

## 🛠️ Solução de Problemas

### TOR não conecta
```bash
sudo systemctl restart tor
sudo tail -f /var/log/tor/tor.log
```

### WiFi não funciona
```bash
sudo systemctl restart hostapd
sudo systemctl status hostapd
```

### Velocidade muito baixa
```bash
# Testar diferentes circuitos
sudo /opt/tor_router/tor_auto_reconnect.sh manual

# Configurar bridges
sudo /opt/tor_router/configure_bridges.sh obfs4
```

### Vazamentos detectados
```bash
# Verificação completa
sudo python3 /opt/tor_router/security_checker.py

# Reconfigurar firewall
sudo /opt/tor_router/setup_advanced_firewall.sh
```

## 📊 Monitoramento

### Logs Importantes
```bash
# Monitor principal
sudo tail -f /var/log/tor_router/monitor.log

# TOR
sudo tail -f /var/log/tor/tor.log

# Reconexões automáticas
sudo tail -f /var/log/tor_router/auto_reconnect.log

# Verificações de segurança
sudo tail -f /var/log/tor_router/security_checker.log
```

### Verificações Automáticas
- **Reconexão TOR**: A cada 30 minutos
- **Verificação de conectividade**: A cada 5 minutos
- **Teste de velocidade**: A cada 5 minutos
- **Verificação de segurança**: A cada hora
- **Limpeza de logs**: Diariamente
- **Backup de dados**: Semanalmente

## 🔒 Segurança

### Verificações Automáticas
- ✅ Vazamentos DNS
- ✅ Vazamentos IP
- ✅ Vazamentos WebRTC
- ✅ Consistência de geolocalização
- ✅ Resistência a fingerprinting
- ✅ Análise de headers HTTP

### Melhores Práticas
1. **Use HTTPS** sempre que possível
2. **Desabilite JavaScript** para máxima segurança
3. **Use Tor Browser** em vez de navegadores comuns
4. **Não faça login** em contas pessoais
5. **Monitore regularmente** a interface web

## 📈 Performance

### Métricas Monitoradas
- Velocidade de download/upload
- Latência da conexão
- Estabilidade do circuito
- Uso de recursos do sistema
- Número de clientes conectados

### Otimizações Automáticas
- Configurações de kernel otimizadas
- Buffers de rede ajustados
- Limites de arquivo aumentados
- Configurações TOR otimizadas

## 🔄 Manutenção

### Automática
- Limpeza de logs antigos
- Rotação de arquivos
- Backup de configurações
- Atualização de bridges
- Verificações de integridade

### Manual
```bash
# Limpeza manual
sudo /opt/tor_router/cleanup_logs.sh

# Backup manual
sudo /opt/tor_router/backup_data.sh

# Atualização de bridges
sudo /opt/tor_router/update_bridges.sh
```

## 📚 Documentação

- **Manual Completo**: `MANUAL_ROTEADOR_TOR.md`
- **Logs de Sistema**: `/var/log/tor_router/`
- **Configurações**: `/etc/tor_router/`
- **Scripts**: `/opt/tor_router/`

## 🆘 Suporte

### Em caso de problemas:

1. **Verifique o status**: `tor-router-status`
2. **Consulte os logs**: `sudo journalctl -u tor-monitor -f`
3. **Execute diagnóstico**: `sudo python3 /opt/tor_router/security_checker.py`
4. **Consulte o manual**: `MANUAL_ROTEADOR_TOR.md`

### Recuperação de emergência:
```bash
# Reset completo
sudo /opt/tor_router/stop_tor_router.sh
sudo ./install_complete_system.sh
```

## ⚠️ Avisos Importantes

- **Use responsavelmente** e respeite as leis locais
- **Não use para atividades ilegais**
- **Monitore regularmente** a segurança
- **Mantenha o sistema atualizado**
- **Faça backup** das configurações importantes

## 🌟 Características Avançadas

### Bridges TOR
- Suporte a obfs4, snowflake e meek
- Atualização automática de bridges
- Configuração dinâmica baseada na localização

### Monitoramento Inteligente
- Detecção automática de problemas
- Alertas em tempo real
- Análise de tendências
- Relatórios detalhados

### Interface Web Responsiva
- Design moderno e intuitivo
- Compatível com dispositivos móveis
- Atualizações em tempo real
- Gráficos interativos

---

## 🎉 Pronto para usar!

Após a instalação, seu roteador TOR estará funcionando automaticamente. Conecte seus dispositivos à rede WiFi e navegue com total anonimato!

**Rede WiFi**: `TOR_Router_Secure`  
**Interface Web**: `http://192.168.100.1:8080`

---

**Desenvolvido por Manus AI** | **Versão 1.0** | **Janeiro 2025**

