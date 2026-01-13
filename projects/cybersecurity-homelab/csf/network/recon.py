#!/usr/bin/env python3.14
"""Network Reconnaissance & Enumeration"""
import re
import socket
import json
from typing import List, Dict, Set
from dataclasses import dataclass
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

@dataclass
class SubdomainInfo:
    subdomain: str
    ip_address: str
    status_code: int
    service: str
    technology: str

@dataclass
class PortInfo:
    port: int
    service: str
    state: str
    version: str

class SubdomainEnumerator:
    """Enumerate subdomains"""
    
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev', 'staging',
        'prod', 'backup', 'cdn', 'cloud', 'git', 'svn', 'jenkins', 'vpn',
        'remote', 'intranet', 'portal', 'service', 'support', 'blog',
        'news', 'shop', 'store', 'app', 'apps', 'mobile', 'api-v1',
        'api-v2', 'beta', 'preview', 'sandbox', 'demo', 'test-api'
    ]
    
    def __init__(self, domain: str):
        self.domain = domain
        self.found_subdomains: List[SubdomainInfo] = []
    
    def enumerate(self) -> List[SubdomainInfo]:
        """Enumerate subdomains"""
        print(f"{Fore.YELLOW}[*] Enumerating subdomains for {self.domain}{Style.RESET_ALL}")
        
        for subdomain in self.COMMON_SUBDOMAINS:
            full_domain = f"{subdomain}.{self.domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                info = SubdomainInfo(
                    subdomain=full_domain,
                    ip_address=ip,
                    status_code=200,
                    service=self._detect_service(subdomain),
                    technology='Unknown'
                )
                self.found_subdomains.append(info)
                print(f"{Fore.GREEN}[+] Found: {full_domain} ({ip}){Style.RESET_ALL}")
            except socket.gaierror:
                pass
        
        return self.found_subdomains
    
    @staticmethod
    def _detect_service(subdomain: str) -> str:
        services = {
            'mail': 'Email Server',
            'ftp': 'FTP Server',
            'admin': 'Admin Panel',
            'api': 'API Server',
            'git': 'Version Control',
            'jenkins': 'CI/CD',
            'vpn': 'VPN Gateway',
            'cdn': 'CDN',
        }
        return services.get(subdomain, 'Web Server')

class PortScanner:
    """Scan open ports"""
    
    COMMON_PORTS = {
        22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL',
        5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP Alt',
        8443: 'HTTPS Alt', 27017: 'MongoDB', 5601: 'Kibana',
        9200: 'Elasticsearch', 3389: 'RDP', 445: 'SMB'
    }
    
    def __init__(self, target: str):
        self.target = target
        self.open_ports: List[PortInfo] = []
    
    def scan(self) -> List[PortInfo]:
        """Scan common ports"""
        print(f"{Fore.YELLOW}[*] Scanning {self.target}{Style.RESET_ALL}")
        
        for port, service in self.COMMON_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, port))
                sock.close()
                
                if result == 0:
                    port_info = PortInfo(
                        port=port,
                        service=service,
                        state='OPEN',
                        version='Unknown'
                    )
                    self.open_ports.append(port_info)
                    print(f"{Fore.GREEN}[+] Port {port}/{service} OPEN{Style.RESET_ALL}")
            except Exception as e:
                pass
        
        return self.open_ports

class VulnScanner:
    """Scan for known vulnerabilities"""
    
    CVE_DATABASE = {
        'Apache': [('CVE-2021-41773', 9.8, 'Path Traversal')],
        'Nginx': [('CVE-2021-23017', 7.5, 'Off-by-one')],
        'OpenSSL': [('CVE-2021-3711', 9.8, 'Buffer overflow')],
        'Tomcat': [('CVE-2021-42340', 9.8, 'RCE')],
    }
    
    def __init__(self, service: str, version: str):
        self.service = service
        self.version = version
    
    def scan(self) -> List[Dict]:
        """Check for known CVEs"""
        vulns = []
        
        for service, cves in self.CVE_DATABASE.items():
            if service.lower() in self.service.lower():
                for cve_id, score, vuln_type in cves:
                    vulns.append({
                        'cve_id': cve_id,
                        'severity': score,
                        'type': vuln_type,
                        'service': service,
                        'version': self.version
                    })
        
        return vulns

class NetworkRecon:
    """Complete network reconnaissance"""
    
    def __init__(self, target: str):
        self.target = target
        self.subdomain_enum = SubdomainEnumerator(target)
        self.port_scanner = PortScanner(target)
        self.results = {}
    
    def run_full_recon(self) -> Dict:
        """Run complete reconnaissance"""
        print(f"\n{Fore.CYAN}[*] === NETWORK RECONNAISSANCE ==={Style.RESET_ALL}\n")
        
        # Enumerate subdomains
        subdomains = self.subdomain_enum.enumerate()
        
        # Scan ports
        ports = self.port_scanner.scan()
        
        # Scan for vulns
        vulns = []
        for port_info in ports:
            vuln_scanner = VulnScanner(port_info.service, 'Unknown')
            vulns.extend(vuln_scanner.scan())
        
        return {
            'target': self.target,
            'subdomains_found': len(subdomains),
            'open_ports': len(ports),
            'vulnerabilities': len(vulns),
            'subdomains': [
                {'domain': s.subdomain, 'ip': s.ip_address, 'service': s.service}
                for s in subdomains
            ],
            'ports': [
                {'port': p.port, 'service': p.service, 'state': p.state}
                for p in ports
            ],
            'vulns': vulns[:10]
        }

if __name__ == '__main__':
    print(f"{Fore.CYAN}[*] Network Recon Ready{Style.RESET_ALL}")
