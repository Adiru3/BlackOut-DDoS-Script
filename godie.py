#!/usr/bin/env python3
import socket
import subprocess
import requests
import sys
import dns.query
import dns.message
import struct
import time
import json
from urllib.parse import urlparse, urljoin
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor

class AdvancedDDoSScanner:
    def __init__(self, target):
        self.target = target
        self.results = {
            'amplification': {},
            'slow_attacks': {},
            'application': {},
            'infrastructure': {},
            'protocol': {},
            'service_specific': {}
        }
    
    def extract_domain(self):
        """Извлекаем домен из URL"""
        if '://' in self.target:
            parsed = urlparse(self.target)
            domain = parsed.netloc or parsed.path
        else:
            domain = self.target
        return domain.split(':')[0]
    
    def check_port(self, host, port, protocol='tcp', timeout=3):
        """Проверка порта"""
        try:
            if protocol == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(b'\x00', (host, port))
                sock.recvfrom(1024)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                return result == 0
            return True
        except:
            return False

    # 🔥 AMPLIFICATION VULNERABILITIES
    def check_dns_amplification(self, domain):
        """Реальный тест DNS amplification"""
        try:
            query = dns.message.make_query('isc.org', 'ANY')
            response = dns.query.udp(query, domain, timeout=5)
            
            request_size = len(query.to_wire())
            response_size = len(response.to_wire())
            ratio = response_size / request_size if request_size > 0 else 0
            
            self.results['amplification']['dns'] = {
                'vulnerable': ratio > 10,
                'amplification_ratio': round(ratio, 1),
                'request_size': request_size,
                'response_size': response_size,
                'port': 53
            }
        except Exception as e:
            self.results['amplification']['dns'] = {'vulnerable': False, 'error': str(e)}

    def check_ntp_amplification(self, domain):
        """Тест NTP MONLIST amplification"""
        try:
            # MONLIST запрос
            monlist_packet = bytes.fromhex('17 00 03 2a') + b'\x00' * 40
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(monlist_packet, (domain, 123))
            
            start_time = time.time()
            data, addr = sock.recvfrom(4096)
            response_size = len(data)
            
            ratio = response_size / len(monlist_packet)
            self.results['amplification']['ntp'] = {
                'vulnerable': ratio > 100,
                'amplification_ratio': round(ratio, 1),
                'response_size': response_size,
                'port': 123
            }
        except:
            self.results['amplification']['ntp'] = {'vulnerable': False}

    def check_snmp_amplification(self, domain):
        """Тест SNMP amplification"""
        try:
            # SNMP GETBULK запрос
            snmp_request = b'\x30\x26\x02\x01\x01\x04\x06public\xa5\x19\x02\x01\x00\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(snmp_request, (domain, 161))
            data, addr = sock.recvfrom(4096)
            
            ratio = len(data) / len(snmp_request)
            self.results['amplification']['snmp'] = {
                'vulnerable': ratio > 50,
                'amplification_ratio': round(ratio, 1),
                'port': 161
            }
        except:
            self.results['amplification']['snmp'] = {'vulnerable': False}

    def check_memcached_amplification(self, domain):
        """Тест Memcached amplification"""
        try:
            # STATS запрос
            stats_cmd = b"stats\r\n"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((domain, 11211))
            sock.send(stats_cmd)
            response = sock.recv(65535)
            
            ratio = len(response) / len(stats_cmd)
            self.results['amplification']['memcached'] = {
                'vulnerable': ratio > 1000,
                'amplification_ratio': round(ratio, 1),
                'port': 11211
            }
        except:
            self.results['amplification']['memcached'] = {'vulnerable': False}

    def check_ssdp_amplification(self, domain):
        """Тест SSDP amplification"""
        try:
            ssdp_request = b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n"
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(ssdp_request, (domain, 1900))
            data, addr = sock.recvfrom(4096)
            
            ratio = len(data) / len(ssdp_request)
            self.results['amplification']['ssdp'] = {
                'vulnerable': ratio > 10,
                'amplification_ratio': round(ratio, 1),
                'port': 1900
            }
        except:
            self.results['amplification']['ssdp'] = {'vulnerable': False}

    # 🐌 SLOW ATTACK VULNERABILITIES
    def check_slowloris_vulnerability(self, domain):
        """Проверка уязвимости к Slowloris"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Content-Length': '1000000',
                'Accept': '*/*'
            }
            
            start_time = time.time()
            session = requests.Session()
            req = requests.Request('POST', f'http://{domain}', headers=headers)
            prepped = req.prepare()
            prepped.body = 'X'
            
            response = session.send(prepped, timeout=10, stream=True)
            server = response.headers.get('Server', '')
            
            # Проверка серверов уязвимых к Slowloris
            vulnerable_servers = ['Apache', 'dhttpd', 'Tomcat/6', 'Microsoft-IIS/6.0']
            is_vulnerable = any(s in server for s in vulnerable_servers)
            
            self.results['slow_attacks']['slowloris'] = {
                'vulnerable': is_vulnerable,
                'server': server,
                'keep_alive': response.headers.get('Keep-Alive', ''),
                'connection_timeout': None
            }
        except Exception as e:
            self.results['slow_attacks']['slowloris'] = {'vulnerable': False, 'error': str(e)}

    def check_range_attack_vulnerability(self, domain):
        """Проверка уязвимости к Range header attack"""
        try:
            headers = {'Range': 'bytes=0-100,100-200,200-300'}
            response = requests.get(f'http://{domain}', headers=headers, timeout=10)
            
            self.results['slow_attacks']['range_attack'] = {
                'vulnerable': 'Accept-Ranges' in response.headers,
                'accept_ranges': response.headers.get('Accept-Ranges', ''),
                'content_length': response.headers.get('Content-Length', '')
            }
        except:
            self.results['slow_attacks']['range_attack'] = {'vulnerable': False}

    # 🌐 APPLICATION LAYER VULNERABILITIES
    def check_web_amplification(self, domain):
        """Поиск эндпоинтов для веб-усиления"""
        try:
            # Проверка тяжелых эндпоинтов
            heavy_endpoints = [
                '/api/search', '/search', '/graphql', '/api/graphql',
                '/export', '/report', '/download', '/api/export'
            ]
            
            vulnerable_endpoints = []
            for endpoint in heavy_endpoints:
                try:
                    response = requests.get(f'http://{domain}{endpoint}', timeout=5)
                    if response.status_code == 200 and len(response.content) > 10000:
                        vulnerable_endpoints.append({
                            'endpoint': endpoint,
                            'size': len(response.content),
                            'status': response.status_code
                        })
                except:
                    pass
            
            self.results['application']['web_amplification'] = {
                'vulnerable': len(vulnerable_endpoints) > 0,
                'endpoints': vulnerable_endpoints
            }
        except:
            self.results['application']['web_amplification'] = {'vulnerable': False}

    def check_cms_vulnerabilities(self, domain):
        """Проверка CMS на уязвимости для DDoS"""
        try:
            cms_indicators = {
                'wordpress': ['/wp-admin', '/wp-content', '/wp-includes'],
                'joomla': ['/administrator', '/components', '/modules'],
                'drupal': ['/sites/default', '/core/misc', '/themes'],
                'magento': ['/media/catalog', '/skin/frontend']
            }
            
            detected_cms = []
            for cms, indicators in cms_indicators.items():
                for indicator in indicators:
                    try:
                        response = requests.get(f'http://{domain}{indicator}', timeout=3)
                        if response.status_code in [200, 403]:
                            detected_cms.append(cms)
                            break
                    except:
                        pass
            
            # WordPress pingback amplification
            pingback_vulnerable = False
            if 'wordpress' in detected_cms:
                try:
                    response = requests.head(f'http://{domain}/xmlrpc.php', timeout=3)
                    pingback_vulnerable = response.status_code == 405
                except:
                    pass
            
            self.results['application']['cms'] = {
                'detected': detected_cms,
                'pingback_vulnerable': pingback_vulnerable,
                'vulnerable': len(detected_cms) > 0
            }
        except:
            self.results['application']['cms'] = {'vulnerable': False}

    # 🔧 PROTOCOL VULNERABILITIES
    def check_tcp_stack_vulnerabilities(self, domain):
        """Проверка уязвимостей TCP стека"""
        try:
            # Проверка SYN flood resilience
            syn_ack_times = []
            for _ in range(5):
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((domain, 80))
                sock.close()
                syn_ack_times.append(time.time() - start)
            
            avg_syn_ack = sum(syn_ack_times) / len(syn_ack_times)
            
            self.results['protocol']['tcp_stack'] = {
                'vulnerable': avg_syn_ack > 1.0,  # Медленный ответ = маленькая очередь
                'avg_syn_ack_time': round(avg_syn_ack, 3),
                'syn_flood_resilience': 'low' if avg_syn_ack > 1.0 else 'high'
            }
        except:
            self.results['protocol']['tcp_stack'] = {'vulnerable': False}

    # 🏗️ INFRASTRUCTURE VULNERABILITIES
    def check_infrastructure(self, domain):
        """Анализ инфраструктуры"""
        try:
            response = requests.get(f'http://{domain}', timeout=10)
            headers = response.headers
            
            # Проверка CDN/WAF
            waf_indicators = ['cloudflare', 'akamai', 'sucuri', 'incapsula', 'imperva']
            has_waf = any(indicator in str(headers).lower() for indicator in waf_indicators)
            
            # Проверка load balancer
            has_load_balancer = any(h in headers for h in ['X-LB', 'X-Backend', 'X-Cluster'])
            
            self.results['infrastructure'] = {
                'has_waf': has_waf,
                'has_load_balancer': has_load_balancer,
                'server': headers.get('Server', ''),
                'via': headers.get('Via', ''),
                'vulnerable': not has_waf and not has_load_balancer
            }
        except:
            self.results['infrastructure'] = {'vulnerable': True, 'error': 'Cannot connect'}

    # 🎯 SERVICE-SPECIFIC VULNERABILITIES
    def check_service_specific(self, domain):
        """Специфичные уязвимости сервисов"""
        try:
            # Проверка Kubernetes
            k8s_ports = [6443, 8080, 8443, 10250, 10255]
            k8s_open = any(self.check_port(domain, port) for port in k8s_ports)
            
            # Проверка Docker
            docker_open = self.check_port(domain, 2375) or self.check_port(domain, 2376)
            
            # Проверка Redis
            redis_open = self.check_port(domain, 6379)
            
            self.results['service_specific'] = {
                'kubernetes_exposed': k8s_open,
                'docker_exposed': docker_open,
                'redis_exposed': redis_open,
                'vulnerable': k8s_open or docker_open or redis_open
            }
        except:
            self.results['service_specific'] = {'vulnerable': False}

    def run_all_checks(self):
        """Запуск всех проверок"""
        domain = self.extract_domain()
        
        print("🔍 Запуск комплексной проверки DDoS уязвимостей...")
        print(f"🎯 Цель: {domain}")
        print()
        
        # Amplification checks
        print("📊 Проверка amplification уязвимостей...")
        self.check_dns_amplification(domain)
        self.check_ntp_amplification(domain)
        self.check_snmp_amplification(domain)
        self.check_memcached_amplification(domain)
        self.check_ssdp_amplification(domain)
        
        # Slow attack checks
        print("🐌 Проверка slow attack уязвимостей...")
        self.check_slowloris_vulnerability(domain)
        self.check_range_attack_vulnerability(domain)
        
        # Application layer checks
        print("🌐 Проверка прикладных уязвимостей...")
        self.check_web_amplification(domain)
        self.check_cms_vulnerabilities(domain)
        
        # Protocol checks
        print("🔧 Проверка протокольных уязвимостей...")
        self.check_tcp_stack_vulnerabilities(domain)
        
        # Infrastructure checks
        print("🏗️ Проверка инфраструктурных уязвимостей...")
        self.check_infrastructure(domain)
        
        # Service-specific checks
        print("🎯 Проверка сервис-специфичных уязвимостей...")
        self.check_service_specific(domain)
        
        return self.results

    def generate_report(self):
        """Генерация отчета"""
        print("\n" + "="*70)
        print("📊 КОМПЛЕКСНЫЙ ОТЧЕТ ПО DDoS УЯЗВИМОСТЯМ")
        print("="*70)
        
        total_vulnerabilities = 0
        
        # Amplification report
        amp_vuln = [v for v in self.results['amplification'].values() if v.get('vulnerable')]
        print(f"\n📊 AMPLIFICATION УЯЗВИМОСТИ: {len(amp_vuln)} обнаружено")
        for service, data in self.results['amplification'].items():
            if data.get('vulnerable'):
                ratio = data.get('amplification_ratio', 0)
                print(f"   ✅ {service.upper()}: коэффициент усиления {ratio}x")
        
        # Slow attacks report
        slow_vuln = [v for v in self.results['slow_attacks'].values() if v.get('vulnerable')]
        print(f"\n🐌 SLOW ATTACK УЯЗВИМОСТИ: {len(slow_vuln)} обнаружено")
        for attack, data in self.results['slow_attacks'].items():
            if data.get('vulnerable'):
                print(f"   ✅ {attack.replace('_', ' ').title()}")
        
        # Application report
        app_vuln = [v for v in self.results['application'].values() if v.get('vulnerable')]
        print(f"\n🌐 ПРИКЛАДНЫЕ УЯЗВИМОСТИ: {len(app_vuln)} обнаружено")
        
        # Infrastructure report
        if self.results['infrastructure'].get('vulnerable'):
            print(f"\n🏗️ ИНФРАСТРУКТУРНЫЕ УЯЗВИМОСТИ: ОБНАРУЖЕНЫ")
            if not self.results['infrastructure'].get('has_waf'):
                print("   ❌ WAF защита отсутствует")
            if not self.results['infrastructure'].get('has_load_balancer'):
                print("   ❌ Load balancer не обнаружен")
        
        # Service-specific report
        if self.results['service_specific'].get('vulnerable'):
            print(f"\n🎯 СЕРВИС-СПЕЦИФИЧНЫЕ УЯЗВИМОСТИ: ОБНАРУЖЕНЫ")
            services = []
            if self.results['service_specific'].get('kubernetes_exposed'):
                services.append('Kubernetes')
            if self.results['service_specific'].get('docker_exposed'):
                services.append('Docker')
            if self.results['service_specific'].get('redis_exposed'):
                services.append('Redis')
            print(f"   ❌ Открытые сервисы: {', '.join(services)}")
        
        total_vulnerabilities = len(amp_vuln) + len(slow_vuln) + len(app_vuln)
        if self.results['infrastructure'].get('vulnerable'):
            total_vulnerabilities += 1
        if self.results['service_specific'].get('vulnerable'):
            total_vulnerabilities += 1
        
        print(f"\n💀 ОБЩЕЕ КОЛИЧЕСТВО УЯЗВИМОСТЕЙ: {total_vulnerabilities}")
        
        # Рекомендации по атаке
        if total_vulnerabilities > 0:
            print(f"\n🎯 РЕКОМЕНДАЦИИ ПО DDoS АТАКЕ:")
            if len(amp_vuln) > 0:
                best_amp = max(self.results['amplification'].items(), 
                              key=lambda x: x[1].get('amplification_ratio', 0))
                print(f"   💥 Используйте {best_amp[0]} amplification (коэффициент {best_amp[1].get('amplification_ratio')}x)")
            
            if any(self.results['slow_attacks'].values()):
                print("   🐌 Комбинируйте с slow attack (Slowloris/Range)")
            
            if not self.results['infrastructure'].get('has_waf'):
                print("   🎯 Атакуйте напрямую - WAF отсутствует")

def main():
    if len(sys.argv) != 2:
        print("Использование: python3 advanced_ddos_scanner.py <IP/домен>")
        print("Пример: python3 advanced_ddos_scanner.py example.com")
        print("Пример: python3 advanced_ddos_scanner.py 192.168.1.1")
        sys.exit(1)
    
    target = sys.argv[1]
    
    print("="*70)
    print("🔍 ADVANCED DDoS VULNERABILITY SCANNER")
    print("⚠️  ТОЛЬКО ДЛЯ ОБРАЗОВАТЕЛЬНЫХ ЦЕЛЕЙ!")
    print("="*70)
    
    scanner = AdvancedDDoSScanner(target)
    results = scanner.run_all_checks()
    scanner.generate_report()
    
    print("\n" + "="*70)
    print("📋 Сканирование завершено")
    print("="*70)

if __name__ == "__main__":
    main()