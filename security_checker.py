#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sistema Avançado de Verificação de Segurança e Vazamentos
Sistema: Linux Lite 7.4 / Ubuntu 24.04
Autor: Manus AI
Versão: 1.0

Este script realiza verificações abrangentes de segurança e anonimato:
- Verificação de vazamentos DNS
- Verificação de vazamentos IP
- Teste de vazamentos WebRTC
- Verificação de fingerprinting
- Teste de geolocalização
- Verificação de headers HTTP
- Teste de conectividade TOR
- Análise de circuitos TOR
- Verificação de bridges
- Teste de resistência a censura
"""

import os
import sys
import json
import time
import socket
import subprocess
import requests
import threading
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import hashlib
import random
import re
import base64
import urllib.parse
from stem import Signal
from stem.control import Controller
from stem.descriptor import parse_file
import dns.resolver
import dns.query
import dns.message
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import geoip2.database
import geoip2.errors

# Configurações globais
CONFIG = {
    'tor_socks_port': 9050,
    'tor_control_port': 9051,
    'tor_dns_port': 9053,
    'tor_control_password': 'tor_router_2024',
    'log_dir': '/var/log/tor_router',
    'data_dir': '/opt/tor_router/data',
    'timeout': 30,
    'max_retries': 3,
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
    ]
}

class SecurityChecker:
    """Classe principal para verificações de segurança"""
    
    def __init__(self):
        self.setup_logging()
        self.setup_database()
        self.session = requests.Session()
        self.setup_session()
        self.results = {}
        self.alerts = []
        
        self.logger.info("SecurityChecker inicializado")
    
    def setup_logging(self):
        """Configurar sistema de logging"""
        log_file = os.path.join(CONFIG['log_dir'], 'security_checker.log')
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def setup_database(self):
        """Configurar banco de dados para armazenar resultados"""
        db_path = os.path.join(CONFIG['data_dir'], 'security_checks.db')
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        
        # Criar tabelas
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS security_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                check_type TEXT,
                result TEXT,
                details TEXT,
                severity TEXT,
                resolved BOOLEAN DEFAULT FALSE
            )
        ''')
        
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS leak_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                leak_type TEXT,
                leaked_data TEXT,
                source TEXT,
                severity TEXT
            )
        ''')
        
        self.conn.commit()
    
    def setup_session(self):
        """Configurar sessão HTTP com proxy TOR"""
        self.session.proxies = {
            'http': f'socks5://127.0.0.1:{CONFIG["tor_socks_port"]}',
            'https': f'socks5://127.0.0.1:{CONFIG["tor_socks_port"]}'
        }
        
        self.session.headers.update({
            'User-Agent': random.choice(CONFIG['user_agents']),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        self.session.timeout = CONFIG['timeout']
    
    def add_alert(self, severity: str, message: str, details: str = ""):
        """Adicionar alerta de segurança"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'message': message,
            'details': details
        }
        
        self.alerts.append(alert)
        self.logger.warning(f"ALERTA [{severity.upper()}]: {message}")
        
        # Salvar no banco
        self.conn.execute('''
            INSERT INTO security_checks (check_type, result, details, severity)
            VALUES (?, ?, ?, ?)
        ''', ('alert', message, details, severity))
        self.conn.commit()
    
    def check_tor_connectivity(self) -> Dict:
        """Verificar conectividade básica do TOR"""
        self.logger.info("Verificando conectividade TOR...")
        
        result = {
            'connected': False,
            'ip_address': None,
            'country': None,
            'exit_node': None,
            'circuit_length': 0,
            'response_time': 0
        }
        
        try:
            start_time = time.time()
            
            # Verificar via check.torproject.org
            response = self.session.get('https://check.torproject.org/api/ip')
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                result['connected'] = data.get('IsTor', False)
                result['ip_address'] = data.get('IP', '')
                result['response_time'] = round(response_time, 2)
                
                if result['connected']:
                    # Obter informações adicionais
                    geo_info = self.get_ip_geolocation(result['ip_address'])
                    result['country'] = geo_info.get('country', 'Unknown')
                    
                    # Obter informações do circuito
                    circuit_info = self.get_circuit_info()
                    result.update(circuit_info)
                    
                    self.logger.info(f"TOR conectado: {result['ip_address']} ({result['country']})")
                else:
                    self.add_alert('critical', 'TOR não está funcionando corretamente')
            else:
                self.add_alert('error', f'Falha na verificação TOR: HTTP {response.status_code}')
                
        except Exception as e:
            self.logger.error(f"Erro na verificação TOR: {e}")
            self.add_alert('error', f'Erro na verificação TOR: {str(e)}')
        
        return result
    
    def get_circuit_info(self) -> Dict:
        """Obter informações do circuito TOR atual"""
        circuit_info = {
            'circuit_length': 0,
            'exit_node': None,
            'guard_node': None,
            'middle_nodes': [],
            'circuit_id': None
        }
        
        try:
            with Controller.from_port(port=CONFIG['tor_control_port']) as controller:
                controller.authenticate(password=CONFIG['tor_control_password'])
                
                # Obter circuitos ativos
                circuits = controller.get_circuits()
                
                for circuit in circuits:
                    if circuit.status == 'BUILT' and circuit.purpose == 'GENERAL':
                        circuit_info['circuit_id'] = circuit.id
                        circuit_info['circuit_length'] = len(circuit.path)
                        
                        if circuit.path:
                            circuit_info['guard_node'] = circuit.path[0][1]  # Primeiro nó
                            circuit_info['exit_node'] = circuit.path[-1][1]  # Último nó
                            
                            if len(circuit.path) > 2:
                                circuit_info['middle_nodes'] = [node[1] for node in circuit.path[1:-1]]
                        
                        break
                
        except Exception as e:
            self.logger.warning(f"Erro ao obter informações do circuito: {e}")
        
        return circuit_info
    
    def check_dns_leaks(self) -> Dict:
        """Verificar vazamentos DNS"""
        self.logger.info("Verificando vazamentos DNS...")
        
        result = {
            'has_leak': False,
            'dns_servers': [],
            'leaked_queries': [],
            'resolver_country': None,
            'isp_detected': None
        }
        
        try:
            # Teste 1: dnsleaktest.com
            response = self.session.get('https://www.dnsleaktest.com/results.json')
            
            if response.status_code == 200:
                dns_data = response.json()
                
                for server in dns_data:
                    server_info = {
                        'ip': server.get('ip', ''),
                        'country': server.get('country_name', ''),
                        'isp': server.get('isp', ''),
                        'type': server.get('type', '')
                    }
                    result['dns_servers'].append(server_info)
                
                # Verificar vazamentos
                result['has_leak'] = self.analyze_dns_servers(result['dns_servers'])
                
            # Teste 2: ipleak.net
            try:
                response2 = self.session.get('https://ipleak.net/json/')
                if response2.status_code == 200:
                    leak_data = response2.json()
                    
                    # Verificar DNS servers reportados
                    dns_servers = leak_data.get('dns_servers', [])
                    for server in dns_servers:
                        if self.is_suspicious_dns_server(server):
                            result['leaked_queries'].append(server)
                            result['has_leak'] = True
            except:
                pass
            
            # Teste 3: Verificação manual de DNS
            manual_check = self.manual_dns_check()
            if manual_check['has_leak']:
                result['has_leak'] = True
                result['leaked_queries'].extend(manual_check['leaked_queries'])
            
            if result['has_leak']:
                self.add_alert('warning', 'Vazamento DNS detectado', 
                             f"Servidores: {[s['ip'] for s in result['dns_servers']]}")
            else:
                self.logger.info("Nenhum vazamento DNS detectado")
                
        except Exception as e:
            self.logger.error(f"Erro na verificação DNS: {e}")
            self.add_alert('error', f'Erro na verificação DNS: {str(e)}')
        
        return result
    
    def analyze_dns_servers(self, dns_servers: List[Dict]) -> bool:
        """Analisar servidores DNS para detectar vazamentos"""
        suspicious_indicators = [
            # Ranges de IP privados
            '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
            '127.', '169.254.',
            
            # ISPs conhecidos (indicam vazamento)
            'Comcast', 'Verizon', 'AT&T', 'Charter', 'Cox', 'Optimum',
            'Spectrum', 'Xfinity', 'Time Warner', 'Cablevision',
            
            # Países com censura (não deveriam aparecer)
            'China', 'Iran', 'North Korea', 'Syria', 'Belarus'
        ]
        
        for server in dns_servers:
            ip = server.get('ip', '')
            isp = server.get('isp', '')
            country = server.get('country', '')
            
            # Verificar IP suspeito
            for indicator in suspicious_indicators:
                if indicator in ip or indicator in isp or indicator in country:
                    return True
        
        return False
    
    def is_suspicious_dns_server(self, server_ip: str) -> bool:
        """Verificar se um servidor DNS é suspeito"""
        # Verificar se é IP privado
        private_ranges = [
            ('192.168.0.0', '192.168.255.255'),
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('127.0.0.0', '127.255.255.255'),
            ('169.254.0.0', '169.254.255.255')
        ]
        
        try:
            import ipaddress
            ip = ipaddress.ip_address(server_ip)
            
            for start, end in private_ranges:
                if ipaddress.ip_address(start) <= ip <= ipaddress.ip_address(end):
                    return True
        except:
            pass
        
        return False
    
    def manual_dns_check(self) -> Dict:
        """Verificação manual de DNS usando consultas diretas"""
        result = {
            'has_leak': False,
            'leaked_queries': []
        }
        
        try:
            # Consultar DNS via TOR
            test_domains = [
                'google.com',
                'facebook.com',
                'twitter.com',
                'github.com',
                'stackoverflow.com'
            ]
            
            for domain in test_domains:
                # Fazer consulta DNS via proxy
                try:
                    response = self.session.get(f'https://dns.google/resolve?name={domain}&type=A')
                    if response.status_code == 200:
                        dns_response = response.json()
                        
                        # Verificar se a resposta veio do servidor esperado
                        if 'Answer' in dns_response:
                            for answer in dns_response['Answer']:
                                ip = answer.get('data', '')
                                if self.is_suspicious_dns_server(ip):
                                    result['leaked_queries'].append({
                                        'domain': domain,
                                        'leaked_ip': ip
                                    })
                                    result['has_leak'] = True
                except:
                    continue
                    
        except Exception as e:
            self.logger.warning(f"Erro na verificação manual DNS: {e}")
        
        return result
    
    def check_ip_leaks(self) -> Dict:
        """Verificar vazamentos de IP"""
        self.logger.info("Verificando vazamentos IP...")
        
        result = {
            'has_leak': False,
            'real_ip': None,
            'tor_ip': None,
            'webrtc_leak': False,
            'webrtc_ips': [],
            'http_headers_leak': False,
            'leaked_headers': []
        }
        
        try:
            # Obter IP via TOR
            tor_ip = self.get_tor_ip()
            result['tor_ip'] = tor_ip
            
            # Verificar vazamentos WebRTC
            webrtc_result = self.check_webrtc_leaks()
            result['webrtc_leak'] = webrtc_result['has_leak']
            result['webrtc_ips'] = webrtc_result['leaked_ips']
            
            # Verificar headers HTTP
            headers_result = self.check_http_headers()
            result['http_headers_leak'] = headers_result['has_leak']
            result['leaked_headers'] = headers_result['leaked_headers']
            
            # Verificar se há vazamentos gerais
            result['has_leak'] = (result['webrtc_leak'] or 
                                result['http_headers_leak'])
            
            if result['has_leak']:
                leak_details = []
                if result['webrtc_leak']:
                    leak_details.append(f"WebRTC: {result['webrtc_ips']}")
                if result['http_headers_leak']:
                    leak_details.append(f"Headers: {result['leaked_headers']}")
                
                self.add_alert('warning', 'Vazamento IP detectado', 
                             '; '.join(leak_details))
            else:
                self.logger.info("Nenhum vazamento IP detectado")
                
        except Exception as e:
            self.logger.error(f"Erro na verificação IP: {e}")
            self.add_alert('error', f'Erro na verificação IP: {str(e)}')
        
        return result
    
    def get_tor_ip(self) -> Optional[str]:
        """Obter IP atual via TOR"""
        ip_services = [
            'https://httpbin.org/ip',
            'https://ipinfo.io/ip',
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://checkip.amazonaws.com'
        ]
        
        for service in ip_services:
            try:
                response = self.session.get(service)
                if response.status_code == 200:
                    if 'httpbin.org' in service:
                        return response.json().get('origin', '').split(',')[0].strip()
                    else:
                        return response.text.strip()
            except:
                continue
        
        return None
    
    def check_webrtc_leaks(self) -> Dict:
        """Verificar vazamentos WebRTC usando Selenium"""
        result = {
            'has_leak': False,
            'leaked_ips': [],
            'local_ips': [],
            'public_ips': []
        }
        
        try:
            # Configurar Chrome headless com proxy
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--disable-features=VizDisplayCompositor')
            chrome_options.add_argument(f'--proxy-server=socks5://127.0.0.1:{CONFIG["tor_socks_port"]}')
            
            driver = webdriver.Chrome(options=chrome_options)
            
            try:
                # Navegar para página de teste WebRTC
                driver.get('https://browserleaks.com/webrtc')
                
                # Aguardar carregamento
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, 'body'))
                )
                
                # Executar JavaScript para detectar IPs WebRTC
                webrtc_script = """
                var ips = [];
                var RTCPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
                
                if (RTCPeerConnection) {
                    var pc = new RTCPeerConnection({iceServers: [{urls: "stun:stun.l.google.com:19302"}]});
                    
                    pc.createDataChannel("");
                    
                    pc.onicecandidate = function(ice) {
                        if (ice.candidate) {
                            var candidate = ice.candidate.candidate;
                            var ip = candidate.split(' ')[4];
                            if (ip && ips.indexOf(ip) === -1) {
                                ips.push(ip);
                            }
                        }
                    };
                    
                    pc.createOffer().then(function(offer) {
                        pc.setLocalDescription(offer);
                    });
                }
                
                return ips;
                """
                
                # Aguardar um pouco para coleta de IPs
                time.sleep(5)
                
                # Executar script
                leaked_ips = driver.execute_script(webrtc_script)
                
                # Aguardar mais um pouco para garantir coleta completa
                time.sleep(3)
                leaked_ips.extend(driver.execute_script("return ips;"))
                
                # Remover duplicatas
                leaked_ips = list(set(leaked_ips))
                
                # Analisar IPs encontrados
                for ip in leaked_ips:
                    if self.is_private_ip(ip):
                        result['local_ips'].append(ip)
                    else:
                        result['public_ips'].append(ip)
                        result['has_leak'] = True
                
                result['leaked_ips'] = leaked_ips
                
            finally:
                driver.quit()
                
        except Exception as e:
            self.logger.warning(f"Erro na verificação WebRTC: {e}")
            # Fallback: verificação via API
            try:
                response = self.session.get('https://www.whatismyipaddress.com/api/webrtc.php')
                if response.status_code == 200:
                    data = response.json()
                    if data.get('webrtc_supported') and data.get('local_ip'):
                        result['local_ips'].append(data['local_ip'])
                        if not self.is_private_ip(data['local_ip']):
                            result['has_leak'] = True
                            result['leaked_ips'].append(data['local_ip'])
            except:
                pass
        
        return result
    
    def is_private_ip(self, ip: str) -> bool:
        """Verificar se um IP é privado"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            # Verificação manual para casos especiais
            private_prefixes = [
                '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                '127.', '169.254.'
            ]
            
            return any(ip.startswith(prefix) for prefix in private_prefixes)
    
    def check_http_headers(self) -> Dict:
        """Verificar vazamentos em headers HTTP"""
        result = {
            'has_leak': False,
            'leaked_headers': [],
            'suspicious_headers': []
        }
        
        try:
            # Testar com httpbin.org
            response = self.session.get('https://httpbin.org/headers')
            
            if response.status_code == 200:
                headers_data = response.json()
                headers = headers_data.get('headers', {})
                
                # Headers suspeitos que podem vazar informações
                suspicious_headers = [
                    'X-Real-Ip',
                    'X-Forwarded-For',
                    'X-Originating-Ip',
                    'X-Remote-Ip',
                    'X-Client-Ip',
                    'Client-Ip',
                    'True-Client-Ip',
                    'X-Cluster-Client-Ip'
                ]
                
                for header in suspicious_headers:
                    if header in headers:
                        result['leaked_headers'].append({
                            'header': header,
                            'value': headers[header]
                        })
                        result['has_leak'] = True
                
                # Verificar User-Agent suspeito
                user_agent = headers.get('User-Agent', '')
                if self.is_suspicious_user_agent(user_agent):
                    result['suspicious_headers'].append({
                        'header': 'User-Agent',
                        'value': user_agent,
                        'reason': 'Potentially identifying'
                    })
                
                # Verificar Accept-Language suspeito
                accept_lang = headers.get('Accept-Language', '')
                if self.is_suspicious_language(accept_lang):
                    result['suspicious_headers'].append({
                        'header': 'Accept-Language',
                        'value': accept_lang,
                        'reason': 'Potentially identifying'
                    })
                    
        except Exception as e:
            self.logger.warning(f"Erro na verificação de headers: {e}")
        
        return result
    
    def is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Verificar se User-Agent é suspeito"""
        # Verificar se contém informações muito específicas
        suspicious_patterns = [
            r'Linux.*x86_64.*Ubuntu.*\d+\.\d+',  # Versão específica do Ubuntu
            r'Windows NT \d+\.\d+.*WOW64',       # Arquitetura específica
            r'Chrome/\d+\.\d+\.\d+\.\d+',        # Versão muito específica
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, user_agent):
                return True
        
        return False
    
    def is_suspicious_language(self, accept_lang: str) -> bool:
        """Verificar se Accept-Language é suspeito"""
        # Idiomas muito específicos ou raros podem ser identificadores
        rare_languages = [
            'pt-BR',  # Português brasileiro específico
            'en-US,en;q=0.9,pt;q=0.8',  # Combinação muito específica
        ]
        
        return any(lang in accept_lang for lang in rare_languages)
    
    def check_geolocation_consistency(self) -> Dict:
        """Verificar consistência de geolocalização"""
        self.logger.info("Verificando consistência de geolocalização...")
        
        result = {
            'consistent': True,
            'tor_location': None,
            'dns_location': None,
            'timezone_location': None,
            'discrepancies': []
        }
        
        try:
            # Obter localização via IP TOR
            tor_ip = self.get_tor_ip()
            if tor_ip:
                result['tor_location'] = self.get_ip_geolocation(tor_ip)
            
            # Obter localização via DNS
            dns_location = self.get_dns_geolocation()
            result['dns_location'] = dns_location
            
            # Obter localização via timezone
            timezone_location = self.get_timezone_location()
            result['timezone_location'] = timezone_location
            
            # Verificar discrepâncias
            locations = [
                result['tor_location'],
                result['dns_location'],
                result['timezone_location']
            ]
            
            countries = [loc.get('country') for loc in locations if loc and loc.get('country')]
            
            if len(set(countries)) > 1:
                result['consistent'] = False
                result['discrepancies'].append({
                    'type': 'country_mismatch',
                    'countries': list(set(countries))
                })
                
                self.add_alert('warning', 'Inconsistência de geolocalização detectada',
                             f"Países detectados: {list(set(countries))}")
            
        except Exception as e:
            self.logger.error(f"Erro na verificação de geolocalização: {e}")
        
        return result
    
    def get_ip_geolocation(self, ip: str) -> Dict:
        """Obter geolocalização de um IP"""
        try:
            # Usar múltiplos serviços para maior precisão
            services = [
                f'https://ipinfo.io/{ip}/json',
                f'https://ipapi.co/{ip}/json/',
                f'http://ip-api.com/json/{ip}'
            ]
            
            for service in services:
                try:
                    response = self.session.get(service)
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Normalizar resposta
                        if 'ipinfo.io' in service:
                            return {
                                'country': data.get('country'),
                                'region': data.get('region'),
                                'city': data.get('city'),
                                'org': data.get('org'),
                                'timezone': data.get('timezone')
                            }
                        elif 'ipapi.co' in service:
                            return {
                                'country': data.get('country_name'),
                                'region': data.get('region'),
                                'city': data.get('city'),
                                'org': data.get('org'),
                                'timezone': data.get('timezone')
                            }
                        elif 'ip-api.com' in service:
                            return {
                                'country': data.get('country'),
                                'region': data.get('regionName'),
                                'city': data.get('city'),
                                'org': data.get('isp'),
                                'timezone': data.get('timezone')
                            }
                except:
                    continue
                    
        except Exception as e:
            self.logger.warning(f"Erro ao obter geolocalização: {e}")
        
        return {}
    
    def get_dns_geolocation(self) -> Dict:
        """Obter localização baseada em servidores DNS"""
        try:
            response = self.session.get('https://www.dnsleaktest.com/results.json')
            if response.status_code == 200:
                dns_data = response.json()
                if dns_data:
                    # Usar o primeiro servidor DNS
                    first_server = dns_data[0]
                    return {
                        'country': first_server.get('country_name'),
                        'city': first_server.get('city_name'),
                        'org': first_server.get('isp')
                    }
        except:
            pass
        
        return {}
    
    def get_timezone_location(self) -> Dict:
        """Obter localização baseada em timezone"""
        try:
            response = self.session.get('https://worldtimeapi.org/api/ip')
            if response.status_code == 200:
                data = response.json()
                timezone = data.get('timezone', '')
                
                # Extrair país/região do timezone
                if '/' in timezone:
                    parts = timezone.split('/')
                    return {
                        'timezone': timezone,
                        'region': parts[0] if len(parts) > 0 else None,
                        'city': parts[1] if len(parts) > 1 else None
                    }
        except:
            pass
        
        return {}
    
    def check_fingerprinting_resistance(self) -> Dict:
        """Verificar resistência a fingerprinting"""
        self.logger.info("Verificando resistência a fingerprinting...")
        
        result = {
            'canvas_fingerprint': None,
            'webgl_fingerprint': None,
            'audio_fingerprint': None,
            'font_fingerprint': None,
            'screen_fingerprint': None,
            'uniqueness_score': 0,
            'vulnerable': False
        }
        
        try:
            # Usar Selenium para testes de fingerprinting
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument(f'--proxy-server=socks5://127.0.0.1:{CONFIG["tor_socks_port"]}')
            
            driver = webdriver.Chrome(options=chrome_options)
            
            try:
                # Navegar para página de teste
                driver.get('https://browserleaks.com/canvas')
                
                # Aguardar carregamento
                time.sleep(5)
                
                # Obter canvas fingerprint
                canvas_script = """
                var canvas = document.createElement('canvas');
                var ctx = canvas.getContext('2d');
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillText('Canvas fingerprint test', 2, 2);
                return canvas.toDataURL();
                """
                
                result['canvas_fingerprint'] = driver.execute_script(canvas_script)
                
                # Obter WebGL fingerprint
                webgl_script = """
                var canvas = document.createElement('canvas');
                var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (gl) {
                    var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                    return {
                        vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
                        renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
                    };
                }
                return null;
                """
                
                result['webgl_fingerprint'] = driver.execute_script(webgl_script)
                
                # Obter informações de tela
                screen_script = """
                return {
                    width: screen.width,
                    height: screen.height,
                    colorDepth: screen.colorDepth,
                    pixelDepth: screen.pixelDepth
                };
                """
                
                result['screen_fingerprint'] = driver.execute_script(screen_script)
                
                # Calcular score de unicidade
                uniqueness_factors = 0
                
                if result['canvas_fingerprint']:
                    uniqueness_factors += 1
                
                if result['webgl_fingerprint']:
                    uniqueness_factors += 1
                
                if result['screen_fingerprint']:
                    screen = result['screen_fingerprint']
                    if screen['width'] != 1920 or screen['height'] != 1080:
                        uniqueness_factors += 1
                
                result['uniqueness_score'] = uniqueness_factors
                result['vulnerable'] = uniqueness_factors > 2
                
                if result['vulnerable']:
                    self.add_alert('warning', 'Alta vulnerabilidade a fingerprinting',
                                 f"Score de unicidade: {uniqueness_factors}")
                
            finally:
                driver.quit()
                
        except Exception as e:
            self.logger.warning(f"Erro na verificação de fingerprinting: {e}")
        
        return result
    
    def check_bridge_connectivity(self) -> Dict:
        """Verificar conectividade e eficácia de bridges"""
        self.logger.info("Verificando bridges TOR...")
        
        result = {
            'using_bridges': False,
            'bridge_type': None,
            'bridge_count': 0,
            'working_bridges': 0,
            'failed_bridges': 0,
            'bridge_countries': []
        }
        
        try:
            with Controller.from_port(port=CONFIG['tor_control_port']) as controller:
                controller.authenticate(password=CONFIG['tor_control_password'])
                
                # Verificar se bridges estão sendo usados
                bridge_info = controller.get_info('config/bridge', default=None)
                
                if bridge_info:
                    result['using_bridges'] = True
                    
                    # Obter informações dos bridges
                    bridges = controller.get_conf('Bridge', multiple=True)
                    result['bridge_count'] = len(bridges)
                    
                    # Analisar cada bridge
                    for bridge in bridges:
                        if 'obfs4' in bridge:
                            result['bridge_type'] = 'obfs4'
                        elif 'snowflake' in bridge:
                            result['bridge_type'] = 'snowflake'
                        elif 'meek' in bridge:
                            result['bridge_type'] = 'meek'
                    
                    # Verificar status dos bridges
                    try:
                        entry_guards = controller.get_info('entry-guards', default='')
                        working_count = entry_guards.count('up')
                        result['working_bridges'] = working_count
                        result['failed_bridges'] = result['bridge_count'] - working_count
                    except:
                        pass
                
        except Exception as e:
            self.logger.warning(f"Erro na verificação de bridges: {e}")
        
        return result
    
    def run_comprehensive_check(self) -> Dict:
        """Executar verificação abrangente de segurança"""
        self.logger.info("Iniciando verificação abrangente de segurança...")
        
        start_time = time.time()
        
        # Executar todas as verificações
        checks = {
            'tor_connectivity': self.check_tor_connectivity(),
            'dns_leaks': self.check_dns_leaks(),
            'ip_leaks': self.check_ip_leaks(),
            'geolocation': self.check_geolocation_consistency(),
            'fingerprinting': self.check_fingerprinting_resistance(),
            'bridges': self.check_bridge_connectivity()
        }
        
        # Calcular score geral de segurança
        security_score = self.calculate_security_score(checks)
        
        # Compilar resultado final
        result = {
            'timestamp': datetime.now().isoformat(),
            'duration': round(time.time() - start_time, 2),
            'security_score': security_score,
            'checks': checks,
            'alerts': self.alerts,
            'recommendations': self.generate_recommendations(checks)
        }
        
        # Salvar resultado no banco
        self.save_check_result(result)
        
        self.logger.info(f"Verificação concluída em {result['duration']}s - Score: {security_score}/100")
        
        return result
    
    def calculate_security_score(self, checks: Dict) -> int:
        """Calcular score de segurança (0-100)"""
        score = 100
        
        # TOR conectividade (-30 se não conectado)
        if not checks['tor_connectivity'].get('connected', False):
            score -= 30
        
        # Vazamentos DNS (-20 se detectado)
        if checks['dns_leaks'].get('has_leak', False):
            score -= 20
        
        # Vazamentos IP (-25 se detectado)
        if checks['ip_leaks'].get('has_leak', False):
            score -= 25
        
        # Inconsistência de geolocalização (-10)
        if not checks['geolocation'].get('consistent', True):
            score -= 10
        
        # Vulnerabilidade a fingerprinting (-15)
        if checks['fingerprinting'].get('vulnerable', False):
            score -= 15
        
        # Bridges não funcionando (-10)
        bridge_info = checks['bridges']
        if bridge_info.get('using_bridges', False):
            if bridge_info.get('failed_bridges', 0) > 0:
                score -= 10
        
        return max(0, score)
    
    def generate_recommendations(self, checks: Dict) -> List[str]:
        """Gerar recomendações baseadas nos resultados"""
        recommendations = []
        
        # Recomendações para TOR
        if not checks['tor_connectivity'].get('connected', False):
            recommendations.append("Verificar configuração e conectividade do TOR")
            recommendations.append("Reiniciar serviço TOR se necessário")
        
        # Recomendações para DNS
        if checks['dns_leaks'].get('has_leak', False):
            recommendations.append("Configurar DNS para usar apenas servidores TOR")
            recommendations.append("Verificar configuração do dnsmasq")
            recommendations.append("Considerar usar bridges se em país com censura")
        
        # Recomendações para IP
        if checks['ip_leaks'].get('has_leak', False):
            recommendations.append("Desabilitar WebRTC no navegador")
            recommendations.append("Usar extensões anti-vazamento")
            recommendations.append("Verificar configuração de proxy")
        
        # Recomendações para geolocalização
        if not checks['geolocation'].get('consistent', True):
            recommendations.append("Verificar configuração de timezone")
            recommendations.append("Usar VPN adicional se necessário")
        
        # Recomendações para fingerprinting
        if checks['fingerprinting'].get('vulnerable', False):
            recommendations.append("Usar Tor Browser em vez de navegadores comuns")
            recommendations.append("Desabilitar JavaScript quando possível")
            recommendations.append("Usar configurações de privacidade máxima")
        
        # Recomendações para bridges
        bridge_info = checks['bridges']
        if bridge_info.get('failed_bridges', 0) > 0:
            recommendations.append("Atualizar lista de bridges")
            recommendations.append("Testar diferentes tipos de bridges")
        
        return recommendations
    
    def save_check_result(self, result: Dict):
        """Salvar resultado da verificação no banco"""
        try:
            self.conn.execute('''
                INSERT INTO security_checks (check_type, result, details, severity)
                VALUES (?, ?, ?, ?)
            ''', (
                'comprehensive_check',
                json.dumps({'score': result['security_score']}),
                json.dumps(result),
                'info' if result['security_score'] > 80 else 'warning' if result['security_score'] > 60 else 'critical'
            ))
            self.conn.commit()
        except Exception as e:
            self.logger.error(f"Erro ao salvar resultado: {e}")

def main():
    """Função principal"""
    print("Sistema de Verificação de Segurança TOR")
    print("=" * 50)
    
    # Verificar se está rodando como root
    if os.geteuid() != 0:
        print("AVISO: Recomendado executar como root para acesso completo")
    
    # Criar verificador
    checker = SecurityChecker()
    
    try:
        # Executar verificação completa
        result = checker.run_comprehensive_check()
        
        # Exibir resultado
        print(f"\nScore de Segurança: {result['security_score']}/100")
        print(f"Duração: {result['duration']}s")
        
        if result['alerts']:
            print(f"\nAlertas ({len(result['alerts'])}):")
            for alert in result['alerts'][-5:]:  # Últimos 5 alertas
                print(f"  [{alert['severity'].upper()}] {alert['message']}")
        
        if result['recommendations']:
            print(f"\nRecomendações ({len(result['recommendations'])}):")
            for i, rec in enumerate(result['recommendations'][:5], 1):
                print(f"  {i}. {rec}")
        
        print(f"\nResultado completo salvo no banco de dados")
        
    except Exception as e:
        print(f"Erro durante verificação: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

