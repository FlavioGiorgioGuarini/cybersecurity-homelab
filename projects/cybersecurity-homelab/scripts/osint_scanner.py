#!/usr/bin/env python3.14
"""OSINT Scanner - Automazione per reconnaissance"""

import requests
from bs4 import BeautifulSoup
import json
from datetime import datetime
from colorama import Fore, Style

class OSINTScanner:
    def __init__(self, target):
        self.target = target
        self.results = {}
        self.headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'}
    
    def scan_dns(self):
        print(f"{Fore.YELLOW}[*] Scanning DNS per {self.target}...{Style.RESET_ALL}")
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'test']
        found = []
        for sub in common_subdomains:
            try:
                url = f"http://{sub}.{self.target}"
                resp = requests.head(url, timeout=2, headers=self.headers)
                if resp.status_code < 400:
                    found.append(f"{sub}.{self.target}")
                    print(f"{Fore.GREEN}[+] FOUND: {sub}.{self.target}{Style.RESET_ALL}")
            except:
                pass
        self.results['dns_records'] = found
    
    def scrape_metadata(self):
        print(f"{Fore.YELLOW}[*] Estraendo metadati...{Style.RESET_ALL}")
        try:
            resp = requests.get(f"http://{self.target}", timeout=5, headers=self.headers)
            soup = BeautifulSoup(resp.content, 'html.parser')
            metadata = {'title': soup.title.string if soup.title else 'N/A', 'status_code': resp.status_code}
            self.results['metadata'] = metadata
            print(f"{Fore.GREEN}[+] Metadati: {metadata}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Errore: {e}{Style.RESET_ALL}")
    
    def run_full_scan(self):
        print(f"\n{Fore.CYAN}[*] === OSINT SCAN ==={Style.RESET_ALL}\n")
        self.scan_dns()
        self.scrape_metadata()
        report = {'target': self.target, 'timestamp': datetime.now().isoformat(), 'findings': self.results}
        filename = f"osint_report_{self.target.replace('.', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"{Fore.GREEN}[+] Report salvato: {filename}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3.14 scripts/osint_scanner.py <target>")
        sys.exit(1)
    OSINTScanner(sys.argv[1]).run_full_scan()
