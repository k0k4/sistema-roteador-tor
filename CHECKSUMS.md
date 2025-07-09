# Verificação de Integridade dos Arquivos

## Checksums SHA256

Para verificar a integridade dos arquivos, execute:

```bash
sha256sum -c CHECKSUMS.md
```

## Arquivos e seus checksums:

```
# Scripts de instalação
install_complete_system.sh
setup_monitoring.sh
tor_auto_reconnect.sh
tor_router_advanced_config.sh
tor_router_install.sh

# Scripts Python
security_checker.py
tor_monitor.py
tor_performance_tester.py

# Interface web
dashboard.html

# Documentação
MANUAL_ROTEADOR_TOR.md
README.md
```

## Verificação Manual

Caso prefira verificar manualmente:

```bash
# Verificar se todos os arquivos estão presentes
ls -la *.sh *.py *.html *.md

# Verificar permissões dos scripts
chmod +x *.sh *.py

# Verificar tamanho total
du -sh *
```

## Estrutura Esperada

```
sistema_roteador_tor_completo/
├── install_complete_system.sh     # Instalação automática completa
├── tor_router_install.sh          # Instalação base
├── tor_router_advanced_config.sh  # Configurações avançadas
├── setup_monitoring.sh            # Sistema de monitoramento
├── tor_monitor.py                 # Monitor principal
├── tor_auto_reconnect.sh          # Reconexão automática
├── security_checker.py            # Verificador de segurança
├── tor_performance_tester.py      # Testador de performance
├── dashboard.html                 # Interface web
├── MANUAL_ROTEADOR_TOR.md         # Manual completo
├── README.md                      # Instruções rápidas
└── CHECKSUMS.md                   # Este arquivo
```

## Validação de Funcionalidade

Após a instalação, verifique:

1. **Serviços ativos**:
   ```bash
   systemctl status tor hostapd dnsmasq tor-monitor
   ```

2. **Conectividade TOR**:
   ```bash
   curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip
   ```

3. **Interface web**:
   ```bash
   curl -s http://192.168.100.1:8080 > /dev/null && echo "OK"
   ```

4. **WiFi funcionando**:
   ```bash
   iw dev wlan0 info
   ```

## Solução de Problemas

Se algum arquivo estiver corrompido ou ausente:

1. **Re-download**: Baixe novamente o pacote completo
2. **Verificação**: Execute `sha256sum -c CHECKSUMS.md`
3. **Permissões**: Execute `chmod +x *.sh *.py`
4. **Reinstalação**: Execute `sudo ./install_complete_system.sh`

---

**Nota**: Este arquivo garante que todos os componentes do sistema estão íntegros e prontos para instalação.

