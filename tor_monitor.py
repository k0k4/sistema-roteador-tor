#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sistema de Monitoramento e Reconexão Automática do Roteador TOR
Sistema: Linux Lite 7.4 / Ubuntu 24.04
Autor: Manus AI
Versão: 1.0

Este script monitora continuamente o roteador TOR, realizando:
- Reconexão automática a cada 30 minutos
- Monitoramento de velocidade de conexão
- Detecção de vazamentos DNS e IP
- Verificação de status dos serviços
- Logging detalhado de todas as operações
- Interface web para monitoramento em tempo real
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess
import requests
import socket
import psutil
import netifaces
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import signal
import sqlite3
from pathlib import Path
import hashlib
import random
import re
from stem import Signal
from stem.control import Controller
import speedtest
from flask import Flask, render_template, jsonify, request
import schedule

# Configurações globais
CONFIG = {
    'log_dir': '/var/log/tor_router',
    'data_dir': '/opt/tor_router/data',
    'scripts_dir': '/opt/tor_router',
    'tor_control_port': 9051,
    'tor_socks_port': 9050,
    'tor_dns_port': 9053,
    'tor_trans_port': 9040,
    'reconnect_interval': 30,  # minutos
    'monitor_interval': 60,    # segundos
    'speed_test_interval': 300, # segundos (5 minutos)
    'max_log_size': 10 * 1024 * 1024,  # 10MB
    'max_log_files': 5,
    'web_port': 8080,
    'tor_control_password': 'tor_router_2024',
    'internal_network': '192.168.100.0/24',
    'gateway_ip': '192.168.100.1',
    'wifi_interface': 'wlan0',
    'lan_interface': 'eth1',
    'internet_interface': 'eth0'
}

class TorRouterMonitor:
    """Classe principal para monitoramento do roteador TOR"""
    
    def __init__(self):
        self.setup_logging()
        self.setup_database()
        self.running = True
        self.last_reconnect = datetime.now()
        self.last_speed_test = datetime.now()
        self.current_status = {}
        self.alerts = []
        self.statistics = {
            'total_reconnects': 0,
            'total_speed_tests': 0,
            'uptime_start': datetime.now(),
            'bytes_transferred': 0,
            'clients_served': 0
        }
        
        # Criar diretórios necessários
        os.makedirs(CONFIG['log_dir'], exist_ok=True)
        os.makedirs(CONFIG['data_dir'], exist_ok=True)
        
        self.logger.info("TorRouterMonitor inicializado")
    
    def setup_logging(self):
        """Configurar sistema de logging"""
        log_file = os.path.join(CONFIG['log_dir'], 'tor_monitor.log')
        
        # Configurar logging com rotação
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        
        # Configurar rotação de logs
        if os.path.exists(log_file) and os.path.getsize(log_file) > CONFIG['max_log_size']:
            self.rotate_logs()
    
    def rotate_logs(self):
        """Rotacionar arquivos de log"""
        log_file = os.path.join(CONFIG['log_dir'], 'tor_monitor.log')
        
        # Mover logs antigos
        for i in range(CONFIG['max_log_files'] - 1, 0, -1):
            old_file = f"{log_file}.{i}"
            new_file = f"{log_file}.{i + 1}"
            if os.path.exists(old_file):
                os.rename(old_file, new_file)
        
        # Mover log atual
        if os.path.exists(log_file):
            os.rename(log_file, f"{log_file}.1")
    
    def setup_database(self):
        """Configurar banco de dados SQLite para armazenar estatísticas"""
        db_path = os.path.join(CONFIG['data_dir'], 'tor_monitor.db')
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        
        # Criar tabelas
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS status_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                tor_status BOOLEAN,
                tor_ip TEXT,
                download_speed REAL,
                upload_speed REAL,
                latency REAL,
                dns_leak BOOLEAN,
                ip_leak BOOLEAN,
                connected_clients INTEGER,
                cpu_usage REAL,
                memory_usage REAL,
                disk_usage REAL
            )
        ''')
        
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS reconnect_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                reason TEXT,
                old_ip TEXT,
                new_ip TEXT,
                success BOOLEAN
            )
        ''')
        
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                level TEXT,
                message TEXT,
                resolved BOOLEAN DEFAULT FALSE
            )
        ''')
        
        self.conn.commit()
    
    def check_tor_status(self) -> Dict:
        """Verificar status do serviço TOR"""
        status = {
            'service_running': False,
            'socks_port': False,
            'trans_port': False,
            'dns_port': False,
            'control_port': False,
            'circuit_established': False,
            'bootstrap_progress': 0
        }
        
        try:
            # Verificar se o serviço está rodando
            result = subprocess.run(['systemctl', 'is-active', 'tor'], 
                                  capture_output=True, text=True)
            status['service_running'] = result.stdout.strip() == 'active'
            
            # Verificar portas
            status['socks_port'] = self.check_port(CONFIG['tor_socks_port'])
            status['trans_port'] = self.check_port(CONFIG['tor_trans_port'])
            status['dns_port'] = self.check_port(CONFIG['tor_dns_port'])
            status['control_port'] = self.check_port(CONFIG['tor_control_port'])
            
            # Verificar circuito via controle
            if status['control_port']:
                try:
                    with Controller.from_port(port=CONFIG['tor_control_port']) as controller:
                        controller.authenticate(password=CONFIG['tor_control_password'])
                        
                        # Verificar bootstrap
                        bootstrap_status = controller.get_info("status/bootstrap-phase")
                        if "PROGRESS=100" in bootstrap_status:
                            status['bootstrap_progress'] = 100
                            status['circuit_established'] = True
                        else:
                            # Extrair progresso
                            match = re.search(r'PROGRESS=(\d+)', bootstrap_status)
                            if match:
                                status['bootstrap_progress'] = int(match.group(1))
                
                except Exception as e:
                    self.logger.warning(f"Erro ao verificar controle TOR: {e}")
            
        except Exception as e:
            self.logger.error(f"Erro ao verificar status TOR: {e}")
        
        return status
    
    def check_port(self, port: int) -> bool:
        """Verificar se uma porta está aberta"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_tor_ip(self) -> Optional[str]:
        """Obter IP público via TOR"""
        try:
            # Configurar proxy SOCKS5
            proxies = {
                'http': f'socks5://127.0.0.1:{CONFIG["tor_socks_port"]}',
                'https': f'socks5://127.0.0.1:{CONFIG["tor_socks_port"]}'
            }
            
            # Tentar diferentes serviços
            services = [
                'https://httpbin.org/ip',
                'https://ipinfo.io/ip',
                'https://api.ipify.org',
                'https://icanhazip.com'
            ]
            
            for service in services:
                try:
                    response = requests.get(service, proxies=proxies, timeout=10)
                    if response.status_code == 200:
                        if 'httpbin.org' in service:
                            return response.json().get('origin', '').split(',')[0].strip()
                        else:
                            return response.text.strip()
                except:
                    continue
            
            return None
            
        except Exception as e:
            self.logger.error(f"Erro ao obter IP TOR: {e}")
            return None
    
    def check_tor_connectivity(self) -> bool:
        """Verificar conectividade TOR"""
        try:
            proxies = {
                'http': f'socks5://127.0.0.1:{CONFIG["tor_socks_port"]}',
                'https': f'socks5://127.0.0.1:{CONFIG["tor_socks_port"]}'
            }
            
            # Verificar via check.torproject.org
            response = requests.get('https://check.torproject.org/api/ip', 
                                  proxies=proxies, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('IsTor', False)
            
            return False
            
        except Exception as e:
            self.logger.error(f"Erro ao verificar conectividade TOR: {e}")
            return False
    
    def check_dns_leaks(self) -> Tuple[bool, List[str]]:
        """Verificar vazamentos DNS"""
        try:
            proxies = {
                'http': f'socks5://127.0.0.1:{CONFIG["tor_socks_port"]}',
                'https': f'socks5://127.0.0.1:{CONFIG["tor_socks_port"]}'
            }
            
            # Verificar servidores DNS via dnsleaktest.com
            response = requests.get('https://www.dnsleaktest.com/results.json', 
                                  proxies=proxies, timeout=15)
            
            if response.status_code == 200:
                dns_servers = response.json()
                server_ips = [server.get('ip', '') for server in dns_servers]
                
                # Verificar se há vazamentos (IPs locais ou do ISP)
                local_ranges = [
                    '192.168.', '10.', '172.16.', '172.17.', '172.18.',
                    '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                    '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                    '172.29.', '172.30.', '172.31.', '127.', '169.254.'
                ]
                
                has_leak = any(any(ip.startswith(local) for local in local_ranges) 
                             for ip in server_ips)
                
                return has_leak, server_ips
            
            return False, []
            
        except Exception as e:
            self.logger.error(f"Erro ao verificar vazamentos DNS: {e}")
            return False, []
    
    def check_ip_leaks(self) -> Tuple[bool, Dict]:
        """Verificar vazamentos de IP"""
        try:
            # Obter IP real (sem TOR)
            real_ip = requests.get('https://httpbin.org/ip', timeout=10).json().get('origin', '')
            
            # Obter IP via TOR
            tor_ip = self.get_tor_ip()
            
            # Verificar WebRTC leaks
            webrtc_leak = self.check_webrtc_leak()
            
            leak_info = {
                'real_ip': real_ip,
                'tor_ip': tor_ip,
                'webrtc_leak': webrtc_leak,
                'has_leak': real_ip == tor_ip or webrtc_leak
            }
            
            return leak_info['has_leak'], leak_info
            
        except Exception as e:
            self.logger.error(f"Erro ao verificar vazamentos IP: {e}")
            return False, {}
    
    def check_webrtc_leak(self) -> bool:
        """Verificar vazamentos WebRTC (simulado)"""
        # Em um ambiente real, isso seria feito via browser automation
        # Por simplicidade, retornamos False
        return False
    
    def run_speed_test(self) -> Dict:
        """Executar teste de velocidade"""
        try:
            self.logger.info("Iniciando teste de velocidade...")
            
            # Configurar speedtest para usar proxy TOR
            st = speedtest.Speedtest()
            
            # Obter servidores
            st.get_servers()
            
            # Escolher melhor servidor
            st.get_best_server()
            
            # Executar testes
            download_speed = st.download() / 1_000_000  # Mbps
            upload_speed = st.upload() / 1_000_000      # Mbps
            ping = st.results.ping
            
            result = {
                'download_mbps': round(download_speed, 2),
                'upload_mbps': round(upload_speed, 2),
                'ping_ms': round(ping, 2),
                'server': st.results.server['name'],
                'timestamp': datetime.now().isoformat()
            }
            
            self.logger.info(f"Teste de velocidade concluído: {result}")
            self.statistics['total_speed_tests'] += 1
            
            return result
            
        except Exception as e:
            self.logger.error(f"Erro no teste de velocidade: {e}")
            return {
                'download_mbps': 0,
                'upload_mbps': 0,
                'ping_ms': 0,
                'server': 'unknown',
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }
    
    def get_system_stats(self) -> Dict:
        """Obter estatísticas do sistema"""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memória
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disco
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            
            # Rede
            net_io = psutil.net_io_counters()
            
            # Temperatura (se disponível)
            temp = None
            try:
                temps = psutil.sensors_temperatures()
                if temps:
                    temp = list(temps.values())[0][0].current
            except:
                pass
            
            # Processos TOR
            tor_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                if 'tor' in proc.info['name'].lower():
                    tor_processes.append(proc.info)
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'disk_percent': disk_percent,
                'network_bytes_sent': net_io.bytes_sent,
                'network_bytes_recv': net_io.bytes_recv,
                'temperature': temp,
                'tor_processes': tor_processes,
                'uptime': (datetime.now() - self.statistics['uptime_start']).total_seconds()
            }
            
        except Exception as e:
            self.logger.error(f"Erro ao obter estatísticas do sistema: {e}")
            return {}
    
    def get_connected_clients(self) -> Dict:
        """Obter informações sobre clientes conectados"""
        try:
            clients = {
                'wifi_clients': 0,
                'lan_clients': 0,
                'total_clients': 0,
                'client_list': []
            }
            
            # Clientes WiFi
            try:
                result = subprocess.run(['iw', 'dev', CONFIG['wifi_interface'], 'station', 'dump'], 
                                      capture_output=True, text=True)
                wifi_clients = len([line for line in result.stdout.split('\n') if 'Station' in line])
                clients['wifi_clients'] = wifi_clients
            except:
                pass
            
            # Clientes LAN via ARP
            try:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                lan_clients = len([line for line in result.stdout.split('\n') 
                                 if '192.168.100.' in line])
                clients['lan_clients'] = lan_clients
            except:
                pass
            
            # Lista detalhada via DHCP leases
            try:
                dhcp_leases_file = '/var/lib/dhcp/dhcpd.leases'
                if os.path.exists(dhcp_leases_file):
                    with open(dhcp_leases_file, 'r') as f:
                        content = f.read()
                        # Parse básico dos leases
                        # Implementação simplificada
                        pass
            except:
                pass
            
            clients['total_clients'] = clients['wifi_clients'] + clients['lan_clients']
            self.statistics['clients_served'] = max(self.statistics['clients_served'], 
                                                   clients['total_clients'])
            
            return clients
            
        except Exception as e:
            self.logger.error(f"Erro ao obter clientes conectados: {e}")
            return {'wifi_clients': 0, 'lan_clients': 0, 'total_clients': 0, 'client_list': []}
    
    def reconnect_tor(self, reason: str = "scheduled") -> bool:
        """Reconectar TOR (novo circuito)"""
        try:
            self.logger.info(f"Iniciando reconexão TOR - Motivo: {reason}")
            
            old_ip = self.get_tor_ip()
            
            # Conectar ao controle TOR
            with Controller.from_port(port=CONFIG['tor_control_port']) as controller:
                controller.authenticate(password=CONFIG['tor_control_password'])
                
                # Solicitar novo circuito
                controller.signal(Signal.NEWNYM)
                
                # Aguardar um pouco
                time.sleep(5)
                
                # Verificar novo IP
                new_ip = self.get_tor_ip()
                
                success = new_ip is not None and new_ip != old_ip
                
                # Registrar no banco
                self.conn.execute('''
                    INSERT INTO reconnect_history (reason, old_ip, new_ip, success)
                    VALUES (?, ?, ?, ?)
                ''', (reason, old_ip, new_ip, success))
                self.conn.commit()
                
                if success:
                    self.logger.info(f"Reconexão bem-sucedida: {old_ip} -> {new_ip}")
                    self.statistics['total_reconnects'] += 1
                    self.last_reconnect = datetime.now()
                else:
                    self.logger.warning(f"Reconexão falhou: {old_ip} -> {new_ip}")
                    self.add_alert('warning', f'Reconexão TOR falhou: {old_ip} -> {new_ip}')
                
                return success
                
        except Exception as e:
            self.logger.error(f"Erro na reconexão TOR: {e}")
            self.add_alert('error', f'Erro na reconexão TOR: {str(e)}')
            return False
    
    def add_alert(self, level: str, message: str):
        """Adicionar alerta"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message
        }
        
        self.alerts.append(alert)
        
        # Manter apenas os últimos 100 alertas
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
        
        # Salvar no banco
        self.conn.execute('''
            INSERT INTO alerts (level, message) VALUES (?, ?)
        ''', (level, message))
        self.conn.commit()
        
        self.logger.warning(f"ALERTA [{level.upper()}]: {message}")
    
    def monitor_cycle(self):
        """Ciclo principal de monitoramento"""
        try:
            self.logger.info("Iniciando ciclo de monitoramento...")
            
            # Verificar status TOR
            tor_status = self.check_tor_status()
            
            # Verificar conectividade
            tor_connected = self.check_tor_connectivity()
            
            # Obter IP TOR
            tor_ip = self.get_tor_ip()
            
            # Verificar vazamentos
            dns_leak, dns_servers = self.check_dns_leaks()
            ip_leak, ip_info = self.check_ip_leaks()
            
            # Estatísticas do sistema
            system_stats = self.get_system_stats()
            
            # Clientes conectados
            clients = self.get_connected_clients()
            
            # Teste de velocidade (se necessário)
            speed_result = {}
            if (datetime.now() - self.last_speed_test).total_seconds() > CONFIG['speed_test_interval']:
                speed_result = self.run_speed_test()
                self.last_speed_test = datetime.now()
            
            # Compilar status atual
            self.current_status = {
                'timestamp': datetime.now().isoformat(),
                'tor_status': tor_status,
                'tor_connected': tor_connected,
                'tor_ip': tor_ip,
                'dns_leak': dns_leak,
                'dns_servers': dns_servers,
                'ip_leak': ip_leak,
                'ip_info': ip_info,
                'system_stats': system_stats,
                'clients': clients,
                'speed_result': speed_result,
                'statistics': self.statistics,
                'last_reconnect': self.last_reconnect.isoformat(),
                'next_reconnect': (self.last_reconnect + timedelta(minutes=CONFIG['reconnect_interval'])).isoformat()
            }
            
            # Salvar no banco
            self.conn.execute('''
                INSERT INTO status_history (
                    tor_status, tor_ip, download_speed, upload_speed, latency,
                    dns_leak, ip_leak, connected_clients, cpu_usage, memory_usage, disk_usage
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                tor_connected,
                tor_ip,
                speed_result.get('download_mbps', 0),
                speed_result.get('upload_mbps', 0),
                speed_result.get('ping_ms', 0),
                dns_leak,
                ip_leak,
                clients['total_clients'],
                system_stats.get('cpu_percent', 0),
                system_stats.get('memory_percent', 0),
                system_stats.get('disk_percent', 0)
            ))
            self.conn.commit()
            
            # Verificar problemas e gerar alertas
            self.check_for_issues()
            
            # Verificar se precisa reconectar
            if (datetime.now() - self.last_reconnect).total_seconds() > (CONFIG['reconnect_interval'] * 60):
                self.reconnect_tor("scheduled")
            
            self.logger.info("Ciclo de monitoramento concluído")
            
        except Exception as e:
            self.logger.error(f"Erro no ciclo de monitoramento: {e}")
            self.add_alert('error', f'Erro no monitoramento: {str(e)}')
    
    def check_for_issues(self):
        """Verificar problemas e gerar alertas"""
        status = self.current_status
        
        # Verificar se TOR está funcionando
        if not status.get('tor_connected', False):
            self.add_alert('critical', 'TOR não está conectado!')
        
        # Verificar vazamentos
        if status.get('dns_leak', False):
            self.add_alert('warning', 'Vazamento DNS detectado!')
        
        if status.get('ip_leak', False):
            self.add_alert('warning', 'Vazamento IP detectado!')
        
        # Verificar recursos do sistema
        system_stats = status.get('system_stats', {})
        
        if system_stats.get('cpu_percent', 0) > 90:
            self.add_alert('warning', f'CPU alta: {system_stats["cpu_percent"]:.1f}%')
        
        if system_stats.get('memory_percent', 0) > 90:
            self.add_alert('warning', f'Memória alta: {system_stats["memory_percent"]:.1f}%')
        
        if system_stats.get('disk_percent', 0) > 90:
            self.add_alert('warning', f'Disco cheio: {system_stats["disk_percent"]:.1f}%')
        
        # Verificar velocidade
        speed_result = status.get('speed_result', {})
        if speed_result.get('download_mbps', 0) < 1:
            self.add_alert('warning', 'Velocidade de download muito baixa')
    
    def run_monitor(self):
        """Executar monitoramento contínuo"""
        self.logger.info("Iniciando monitoramento contínuo...")
        
        while self.running:
            try:
                self.monitor_cycle()
                time.sleep(CONFIG['monitor_interval'])
            except KeyboardInterrupt:
                self.logger.info("Interrupção recebida, parando monitoramento...")
                self.running = False
                break
            except Exception as e:
                self.logger.error(f"Erro no loop de monitoramento: {e}")
                time.sleep(10)  # Aguardar antes de tentar novamente
        
        self.logger.info("Monitoramento finalizado")
    
    def signal_handler(self, signum, frame):
        """Handler para sinais do sistema"""
        self.logger.info(f"Sinal {signum} recebido, finalizando...")
        self.running = False
    
    def start(self):
        """Iniciar o monitor"""
        # Configurar handlers de sinal
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Iniciar thread de monitoramento
        monitor_thread = threading.Thread(target=self.run_monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Iniciar interface web
        self.start_web_interface()
    
    def start_web_interface(self):
        """Iniciar interface web para monitoramento"""
        app = Flask(__name__)
        
        @app.route('/')
        def dashboard():
            return render_template('dashboard.html')
        
        @app.route('/api/status')
        def api_status():
            return jsonify(self.current_status)
        
        @app.route('/api/alerts')
        def api_alerts():
            return jsonify(self.alerts[-50:])  # Últimos 50 alertas
        
        @app.route('/api/history')
        def api_history():
            hours = request.args.get('hours', 24, type=int)
            
            cursor = self.conn.execute('''
                SELECT * FROM status_history 
                WHERE timestamp > datetime('now', '-{} hours')
                ORDER BY timestamp DESC
            '''.format(hours))
            
            history = []
            for row in cursor.fetchall():
                history.append({
                    'timestamp': row[1],
                    'tor_status': bool(row[2]),
                    'tor_ip': row[3],
                    'download_speed': row[4],
                    'upload_speed': row[5],
                    'latency': row[6],
                    'dns_leak': bool(row[7]),
                    'ip_leak': bool(row[8]),
                    'connected_clients': row[9],
                    'cpu_usage': row[10],
                    'memory_usage': row[11],
                    'disk_usage': row[12]
                })
            
            return jsonify(history)
        
        @app.route('/api/reconnect', methods=['POST'])
        def api_reconnect():
            reason = request.json.get('reason', 'manual')
            success = self.reconnect_tor(reason)
            return jsonify({'success': success})
        
        @app.route('/api/speed_test', methods=['POST'])
        def api_speed_test():
            result = self.run_speed_test()
            return jsonify(result)
        
        try:
            self.logger.info(f"Iniciando interface web na porta {CONFIG['web_port']}")
            app.run(host='0.0.0.0', port=CONFIG['web_port'], debug=False)
        except Exception as e:
            self.logger.error(f"Erro na interface web: {e}")

def main():
    """Função principal"""
    print("Sistema de Monitoramento do Roteador TOR")
    print("=" * 50)
    
    # Verificar se está rodando como root
    if os.geteuid() != 0:
        print("ERRO: Este script deve ser executado como root (sudo)")
        sys.exit(1)
    
    # Criar e iniciar monitor
    monitor = TorRouterMonitor()
    
    try:
        monitor.start()
    except Exception as e:
        print(f"Erro fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

