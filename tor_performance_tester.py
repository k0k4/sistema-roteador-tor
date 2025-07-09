#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sistema de Teste de Performance TOR
Sistema: Linux Lite 7.4 / Ubuntu 24.04
Autor: Manus AI
Versão: 1.0

Este script realiza testes abrangentes de performance do TOR:
- Teste de velocidade de download/upload
- Teste de latência para diferentes destinos
- Teste de throughput sustentado
- Análise de performance por circuito
- Comparação com conexão direta
- Teste de estabilidade de conexão
- Análise de gargalos de rede
"""

import os
import sys
import time
import json
import threading
import logging
import requests
import subprocess
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import speedtest
import socket
import psutil
from stem import Signal
from stem.control import Controller
import matplotlib.pyplot as plt
import numpy as np

# Configurações globais
CONFIG = {
    'tor_socks_port': 9050,
    'tor_control_port': 9051,
    'tor_control_password': 'tor_router_2024',
    'log_dir': '/var/log/tor_router',
    'data_dir': '/opt/tor_router/data',
    'results_dir': '/opt/tor_router/performance_results',
    'timeout': 60,
    'test_duration': 300,  # 5 minutos
    'test_intervals': 30,  # 30 segundos
    'max_circuits': 5
}

class TorPerformanceTester:
    """Classe principal para testes de performance TOR"""
    
    def __init__(self):
        self.setup_logging()
        self.setup_directories()
        self.results = {}
        self.test_start_time = None
        
        # Configurar sessão TOR
        self.tor_session = requests.Session()
        self.tor_session.proxies = {
            'http': f'socks5://127.0.0.1:{CONFIG["tor_socks_port"]}',
            'https': f'socks5://127.0.0.1:{CONFIG["tor_socks_port"]}'
        }
        self.tor_session.timeout = CONFIG['timeout']
        
        # Configurar sessão direta (para comparação)
        self.direct_session = requests.Session()
        self.direct_session.timeout = CONFIG['timeout']
        
        self.logger.info("TorPerformanceTester inicializado")
    
    def setup_logging(self):
        """Configurar sistema de logging"""
        log_file = os.path.join(CONFIG['log_dir'], 'performance_tester.log')
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def setup_directories(self):
        """Criar diretórios necessários"""
        os.makedirs(CONFIG['results_dir'], exist_ok=True)
        os.makedirs(CONFIG['log_dir'], exist_ok=True)
        os.makedirs(CONFIG['data_dir'], exist_ok=True)
    
    def test_basic_connectivity(self) -> Dict:
        """Teste básico de conectividade TOR"""
        self.logger.info("Testando conectividade básica...")
        
        result = {
            'tor_working': False,
            'tor_ip': None,
            'direct_ip': None,
            'tor_response_time': 0,
            'direct_response_time': 0,
            'ip_changed': False
        }
        
        try:
            # Teste TOR
            start_time = time.time()
            tor_response = self.tor_session.get('https://httpbin.org/ip')
            tor_time = time.time() - start_time
            
            if tor_response.status_code == 200:
                result['tor_working'] = True
                result['tor_ip'] = tor_response.json().get('origin', '').split(',')[0].strip()
                result['tor_response_time'] = round(tor_time, 3)
            
            # Teste direto
            start_time = time.time()
            direct_response = self.direct_session.get('https://httpbin.org/ip')
            direct_time = time.time() - start_time
            
            if direct_response.status_code == 200:
                result['direct_ip'] = direct_response.json().get('origin', '').split(',')[0].strip()
                result['direct_response_time'] = round(direct_time, 3)
            
            # Verificar se IP mudou
            result['ip_changed'] = (result['tor_ip'] != result['direct_ip'] and 
                                  result['tor_ip'] is not None and 
                                  result['direct_ip'] is not None)
            
        except Exception as e:
            self.logger.error(f"Erro no teste de conectividade: {e}")
        
        return result
    
    def test_download_speed(self, file_sizes: List[int] = None) -> Dict:
        """Teste de velocidade de download"""
        if file_sizes is None:
            file_sizes = [1, 5, 10, 25, 50]  # MB
        
        self.logger.info("Testando velocidade de download...")
        
        result = {
            'tor_speeds': {},
            'direct_speeds': {},
            'average_tor_speed': 0,
            'average_direct_speed': 0,
            'speed_ratio': 0
        }
        
        for size_mb in file_sizes:
            self.logger.info(f"Testando download de {size_mb}MB...")
            
            # URL para download de arquivo de teste
            url = f'https://httpbin.org/bytes/{size_mb * 1024 * 1024}'
            
            # Teste via TOR
            tor_speed = self.measure_download_speed(url, self.tor_session, f"{size_mb}MB_tor")
            result['tor_speeds'][f'{size_mb}MB'] = tor_speed
            
            # Teste direto
            direct_speed = self.measure_download_speed(url, self.direct_session, f"{size_mb}MB_direct")
            result['direct_speeds'][f'{size_mb}MB'] = direct_speed
            
            time.sleep(2)  # Pausa entre testes
        
        # Calcular médias
        tor_speeds = [s for s in result['tor_speeds'].values() if s > 0]
        direct_speeds = [s for s in result['direct_speeds'].values() if s > 0]
        
        if tor_speeds:
            result['average_tor_speed'] = round(statistics.mean(tor_speeds), 2)
        
        if direct_speeds:
            result['average_direct_speed'] = round(statistics.mean(direct_speeds), 2)
        
        if result['average_direct_speed'] > 0:
            result['speed_ratio'] = round(result['average_tor_speed'] / result['average_direct_speed'], 3)
        
        return result
    
    def measure_download_speed(self, url: str, session: requests.Session, test_name: str) -> float:
        """Medir velocidade de download para uma URL específica"""
        try:
            start_time = time.time()
            response = session.get(url, stream=True)
            
            if response.status_code != 200:
                return 0
            
            total_size = 0
            chunk_times = []
            
            for chunk in response.iter_content(chunk_size=8192):
                chunk_start = time.time()
                total_size += len(chunk)
                chunk_times.append(time.time() - chunk_start)
            
            total_time = time.time() - start_time
            
            if total_time > 0:
                speed_mbps = (total_size * 8) / (total_time * 1_000_000)  # Mbps
                self.logger.info(f"{test_name}: {speed_mbps:.2f} Mbps em {total_time:.2f}s")
                return round(speed_mbps, 2)
            
        except Exception as e:
            self.logger.warning(f"Erro no teste {test_name}: {e}")
        
        return 0
    
    def test_latency(self, targets: List[str] = None) -> Dict:
        """Teste de latência para diferentes destinos"""
        if targets is None:
            targets = [
                'https://google.com',
                'https://facebook.com',
                'https://github.com',
                'https://stackoverflow.com',
                'https://reddit.com'
            ]
        
        self.logger.info("Testando latência...")
        
        result = {
            'tor_latencies': {},
            'direct_latencies': {},
            'average_tor_latency': 0,
            'average_direct_latency': 0,
            'latency_overhead': 0
        }
        
        for target in targets:
            domain = target.replace('https://', '').replace('http://', '')
            
            # Teste via TOR
            tor_latency = self.measure_latency(target, self.tor_session)
            result['tor_latencies'][domain] = tor_latency
            
            # Teste direto
            direct_latency = self.measure_latency(target, self.direct_session)
            result['direct_latencies'][domain] = direct_latency
            
            time.sleep(1)  # Pausa entre testes
        
        # Calcular médias
        tor_latencies = [l for l in result['tor_latencies'].values() if l > 0]
        direct_latencies = [l for l in result['direct_latencies'].values() if l > 0]
        
        if tor_latencies:
            result['average_tor_latency'] = round(statistics.mean(tor_latencies), 2)
        
        if direct_latencies:
            result['average_direct_latency'] = round(statistics.mean(direct_latencies), 2)
        
        if result['average_direct_latency'] > 0:
            result['latency_overhead'] = round(
                result['average_tor_latency'] - result['average_direct_latency'], 2
            )
        
        return result
    
    def measure_latency(self, url: str, session: requests.Session) -> float:
        """Medir latência para uma URL específica"""
        try:
            start_time = time.time()
            response = session.head(url, allow_redirects=True)
            latency = (time.time() - start_time) * 1000  # ms
            
            if response.status_code < 400:
                return round(latency, 2)
            
        except Exception as e:
            self.logger.warning(f"Erro na medição de latência para {url}: {e}")
        
        return 0
    
    def test_sustained_throughput(self, duration: int = 300) -> Dict:
        """Teste de throughput sustentado"""
        self.logger.info(f"Testando throughput sustentado por {duration}s...")
        
        result = {
            'duration': duration,
            'tor_throughput_history': [],
            'direct_throughput_history': [],
            'tor_average_throughput': 0,
            'direct_average_throughput': 0,
            'tor_stability': 0,
            'direct_stability': 0
        }
        
        # URL para teste contínuo
        test_url = 'https://httpbin.org/bytes/1048576'  # 1MB
        
        start_time = time.time()
        test_interval = 30  # Teste a cada 30 segundos
        
        while time.time() - start_time < duration:
            # Teste TOR
            tor_speed = self.measure_download_speed(test_url, self.tor_session, "sustained_tor")
            result['tor_throughput_history'].append({
                'timestamp': time.time() - start_time,
                'speed': tor_speed
            })
            
            # Teste direto
            direct_speed = self.measure_download_speed(test_url, self.direct_session, "sustained_direct")
            result['direct_throughput_history'].append({
                'timestamp': time.time() - start_time,
                'speed': direct_speed
            })
            
            time.sleep(test_interval)
        
        # Calcular estatísticas
        tor_speeds = [entry['speed'] for entry in result['tor_throughput_history'] if entry['speed'] > 0]
        direct_speeds = [entry['speed'] for entry in result['direct_throughput_history'] if entry['speed'] > 0]
        
        if tor_speeds:
            result['tor_average_throughput'] = round(statistics.mean(tor_speeds), 2)
            result['tor_stability'] = round(1 - (statistics.stdev(tor_speeds) / statistics.mean(tor_speeds)), 3)
        
        if direct_speeds:
            result['direct_average_throughput'] = round(statistics.mean(direct_speeds), 2)
            result['direct_stability'] = round(1 - (statistics.stdev(direct_speeds) / statistics.mean(direct_speeds)), 3)
        
        return result
    
    def test_circuit_performance(self) -> Dict:
        """Testar performance de diferentes circuitos TOR"""
        self.logger.info("Testando performance de circuitos...")
        
        result = {
            'circuits_tested': 0,
            'circuit_results': [],
            'best_circuit': None,
            'worst_circuit': None,
            'average_performance': 0
        }
        
        try:
            with Controller.from_port(port=CONFIG['tor_control_port']) as controller:
                controller.authenticate(password=CONFIG['tor_control_password'])
                
                for i in range(CONFIG['max_circuits']):
                    self.logger.info(f"Testando circuito {i+1}/{CONFIG['max_circuits']}")
                    
                    # Criar novo circuito
                    controller.signal(Signal.NEWNYM)
                    time.sleep(10)  # Aguardar estabelecimento do circuito
                    
                    # Obter informações do circuito
                    circuit_info = self.get_current_circuit_info(controller)
                    
                    # Testar performance
                    perf_start = time.time()
                    
                    # Teste de velocidade rápido
                    speed = self.measure_download_speed(
                        'https://httpbin.org/bytes/5242880',  # 5MB
                        self.tor_session,
                        f"circuit_{i+1}"
                    )
                    
                    # Teste de latência
                    latency = self.measure_latency('https://google.com', self.tor_session)
                    
                    perf_time = time.time() - perf_start
                    
                    circuit_result = {
                        'circuit_number': i + 1,
                        'circuit_info': circuit_info,
                        'download_speed': speed,
                        'latency': latency,
                        'test_duration': round(perf_time, 2),
                        'performance_score': self.calculate_circuit_score(speed, latency)
                    }
                    
                    result['circuit_results'].append(circuit_result)
                    result['circuits_tested'] += 1
                    
                    time.sleep(5)  # Pausa entre circuitos
                
                # Analisar resultados
                if result['circuit_results']:
                    scores = [c['performance_score'] for c in result['circuit_results']]
                    result['average_performance'] = round(statistics.mean(scores), 2)
                    
                    # Melhor e pior circuito
                    best_idx = scores.index(max(scores))
                    worst_idx = scores.index(min(scores))
                    
                    result['best_circuit'] = result['circuit_results'][best_idx]
                    result['worst_circuit'] = result['circuit_results'][worst_idx]
                
        except Exception as e:
            self.logger.error(f"Erro no teste de circuitos: {e}")
        
        return result
    
    def get_current_circuit_info(self, controller) -> Dict:
        """Obter informações do circuito atual"""
        try:
            circuits = controller.get_circuits()
            
            for circuit in circuits:
                if circuit.status == 'BUILT' and circuit.purpose == 'GENERAL':
                    return {
                        'id': circuit.id,
                        'length': len(circuit.path),
                        'guard': circuit.path[0][1] if circuit.path else None,
                        'exit': circuit.path[-1][1] if circuit.path else None,
                        'build_time': circuit.build_time
                    }
        except:
            pass
        
        return {}
    
    def calculate_circuit_score(self, speed: float, latency: float) -> float:
        """Calcular score de performance do circuito"""
        # Score baseado em velocidade e latência
        speed_score = min(speed * 10, 100)  # Max 100 para 10+ Mbps
        latency_score = max(100 - latency / 10, 0)  # Penalizar latência alta
        
        return round((speed_score + latency_score) / 2, 2)
    
    def test_connection_stability(self, duration: int = 600) -> Dict:
        """Testar estabilidade da conexão"""
        self.logger.info(f"Testando estabilidade da conexão por {duration}s...")
        
        result = {
            'duration': duration,
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'success_rate': 0,
            'average_response_time': 0,
            'connection_drops': 0,
            'response_times': []
        }
        
        start_time = time.time()
        test_url = 'https://httpbin.org/status/200'
        
        while time.time() - start_time < duration:
            try:
                request_start = time.time()
                response = self.tor_session.get(test_url)
                response_time = time.time() - request_start
                
                result['total_requests'] += 1
                
                if response.status_code == 200:
                    result['successful_requests'] += 1
                    result['response_times'].append(response_time)
                else:
                    result['failed_requests'] += 1
                
            except Exception as e:
                result['failed_requests'] += 1
                result['connection_drops'] += 1
                self.logger.warning(f"Falha na conexão: {e}")
            
            time.sleep(5)  # Teste a cada 5 segundos
        
        # Calcular estatísticas
        if result['total_requests'] > 0:
            result['success_rate'] = round(
                (result['successful_requests'] / result['total_requests']) * 100, 2
            )
        
        if result['response_times']:
            result['average_response_time'] = round(
                statistics.mean(result['response_times']), 3
            )
        
        return result
    
    def analyze_network_bottlenecks(self) -> Dict:
        """Analisar gargalos de rede"""
        self.logger.info("Analisando gargalos de rede...")
        
        result = {
            'system_resources': {},
            'network_interfaces': {},
            'tor_process': {},
            'bottlenecks': []
        }
        
        try:
            # Recursos do sistema
            result['system_resources'] = {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_io': dict(psutil.disk_io_counters()._asdict()),
                'network_io': dict(psutil.net_io_counters()._asdict())
            }
            
            # Interfaces de rede
            net_interfaces = psutil.net_if_stats()
            for interface, stats in net_interfaces.items():
                result['network_interfaces'][interface] = {
                    'is_up': stats.isup,
                    'speed': stats.speed,
                    'mtu': stats.mtu
                }
            
            # Processo TOR
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                if 'tor' in proc.info['name'].lower():
                    result['tor_process'] = proc.info
                    break
            
            # Identificar gargalos
            if result['system_resources']['cpu_percent'] > 80:
                result['bottlenecks'].append('CPU usage high')
            
            if result['system_resources']['memory_percent'] > 85:
                result['bottlenecks'].append('Memory usage high')
            
            if result['tor_process'].get('cpu_percent', 0) > 50:
                result['bottlenecks'].append('TOR process CPU usage high')
            
        except Exception as e:
            self.logger.error(f"Erro na análise de gargalos: {e}")
        
        return result
    
    def generate_performance_report(self, results: Dict) -> str:
        """Gerar relatório de performance"""
        report_file = os.path.join(
            CONFIG['results_dir'],
            f"performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        # Salvar resultados completos
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Gerar relatório em texto
        text_report = f"""
TOR PERFORMANCE REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*50}

CONNECTIVITY TEST:
- TOR Working: {results.get('connectivity', {}).get('tor_working', 'Unknown')}
- TOR IP: {results.get('connectivity', {}).get('tor_ip', 'Unknown')}
- IP Changed: {results.get('connectivity', {}).get('ip_changed', 'Unknown')}
- TOR Response Time: {results.get('connectivity', {}).get('tor_response_time', 0)}ms

DOWNLOAD SPEED TEST:
- Average TOR Speed: {results.get('download_speed', {}).get('average_tor_speed', 0)} Mbps
- Average Direct Speed: {results.get('download_speed', {}).get('average_direct_speed', 0)} Mbps
- Speed Ratio: {results.get('download_speed', {}).get('speed_ratio', 0)}

LATENCY TEST:
- Average TOR Latency: {results.get('latency', {}).get('average_tor_latency', 0)}ms
- Average Direct Latency: {results.get('latency', {}).get('average_direct_latency', 0)}ms
- Latency Overhead: {results.get('latency', {}).get('latency_overhead', 0)}ms

CIRCUIT PERFORMANCE:
- Circuits Tested: {results.get('circuit_performance', {}).get('circuits_tested', 0)}
- Average Performance: {results.get('circuit_performance', {}).get('average_performance', 0)}

CONNECTION STABILITY:
- Success Rate: {results.get('stability', {}).get('success_rate', 0)}%
- Connection Drops: {results.get('stability', {}).get('connection_drops', 0)}

BOTTLENECKS:
{chr(10).join(f"- {b}" for b in results.get('bottlenecks', {}).get('bottlenecks', []))}

Report saved to: {report_file}
        """
        
        return text_report
    
    def run_comprehensive_test(self) -> Dict:
        """Executar teste abrangente de performance"""
        self.logger.info("Iniciando teste abrangente de performance...")
        
        self.test_start_time = time.time()
        
        results = {
            'test_start': datetime.now().isoformat(),
            'connectivity': {},
            'download_speed': {},
            'latency': {},
            'sustained_throughput': {},
            'circuit_performance': {},
            'stability': {},
            'bottlenecks': {},
            'summary': {}
        }
        
        try:
            # Teste de conectividade
            results['connectivity'] = self.test_basic_connectivity()
            
            if not results['connectivity'].get('tor_working', False):
                self.logger.error("TOR não está funcionando, abortando testes")
                return results
            
            # Teste de velocidade de download
            results['download_speed'] = self.test_download_speed()
            
            # Teste de latência
            results['latency'] = self.test_latency()
            
            # Teste de throughput sustentado (versão reduzida para demo)
            results['sustained_throughput'] = self.test_sustained_throughput(120)  # 2 minutos
            
            # Teste de performance de circuitos
            results['circuit_performance'] = self.test_circuit_performance()
            
            # Teste de estabilidade (versão reduzida)
            results['stability'] = self.test_connection_stability(300)  # 5 minutos
            
            # Análise de gargalos
            results['bottlenecks'] = self.analyze_network_bottlenecks()
            
            # Resumo
            results['summary'] = self.generate_summary(results)
            
            # Duração total
            results['total_duration'] = round(time.time() - self.test_start_time, 2)
            
        except Exception as e:
            self.logger.error(f"Erro durante teste abrangente: {e}")
            results['error'] = str(e)
        
        return results
    
    def generate_summary(self, results: Dict) -> Dict:
        """Gerar resumo dos resultados"""
        summary = {
            'overall_score': 0,
            'performance_grade': 'F',
            'key_metrics': {},
            'recommendations': []
        }
        
        try:
            # Métricas chave
            summary['key_metrics'] = {
                'tor_speed': results.get('download_speed', {}).get('average_tor_speed', 0),
                'speed_ratio': results.get('download_speed', {}).get('speed_ratio', 0),
                'latency_overhead': results.get('latency', {}).get('latency_overhead', 0),
                'stability': results.get('stability', {}).get('success_rate', 0),
                'circuit_performance': results.get('circuit_performance', {}).get('average_performance', 0)
            }
            
            # Calcular score geral
            scores = []
            
            # Score de velocidade (0-25 pontos)
            speed_score = min(summary['key_metrics']['tor_speed'] * 2.5, 25)
            scores.append(speed_score)
            
            # Score de latência (0-25 pontos)
            latency_overhead = summary['key_metrics']['latency_overhead']
            latency_score = max(25 - (latency_overhead / 20), 0)
            scores.append(latency_score)
            
            # Score de estabilidade (0-25 pontos)
            stability_score = summary['key_metrics']['stability'] / 4
            scores.append(stability_score)
            
            # Score de circuitos (0-25 pontos)
            circuit_score = summary['key_metrics']['circuit_performance'] / 4
            scores.append(circuit_score)
            
            summary['overall_score'] = round(sum(scores), 1)
            
            # Grade de performance
            if summary['overall_score'] >= 90:
                summary['performance_grade'] = 'A+'
            elif summary['overall_score'] >= 80:
                summary['performance_grade'] = 'A'
            elif summary['overall_score'] >= 70:
                summary['performance_grade'] = 'B'
            elif summary['overall_score'] >= 60:
                summary['performance_grade'] = 'C'
            elif summary['overall_score'] >= 50:
                summary['performance_grade'] = 'D'
            else:
                summary['performance_grade'] = 'F'
            
            # Recomendações
            if summary['key_metrics']['tor_speed'] < 5:
                summary['recommendations'].append("Considerar usar bridges para melhor velocidade")
            
            if summary['key_metrics']['latency_overhead'] > 1000:
                summary['recommendations'].append("Latência muito alta, verificar circuitos")
            
            if summary['key_metrics']['stability'] < 95:
                summary['recommendations'].append("Problemas de estabilidade detectados")
            
            if len(results.get('bottlenecks', {}).get('bottlenecks', [])) > 0:
                summary['recommendations'].append("Gargalos de sistema detectados")
            
        except Exception as e:
            self.logger.error(f"Erro ao gerar resumo: {e}")
        
        return summary

def main():
    """Função principal"""
    print("Sistema de Teste de Performance TOR")
    print("=" * 50)
    
    # Verificar se está rodando como root
    if os.geteuid() != 0:
        print("AVISO: Recomendado executar como root para acesso completo")
    
    # Criar testador
    tester = TorPerformanceTester()
    
    try:
        # Executar teste completo
        results = tester.run_comprehensive_test()
        
        # Gerar relatório
        report = tester.generate_performance_report(results)
        print(report)
        
        # Salvar gráficos se houver dados de throughput
        if 'sustained_throughput' in results and results['sustained_throughput'].get('tor_throughput_history'):
            tester.create_performance_charts(results)
        
    except Exception as e:
        print(f"Erro durante teste: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

