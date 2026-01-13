#!/usr/bin/env python3.14
"""Network Scanner"""

import socket
import json
from datetime import datetime
from colorama import Fore, Style

class NetworkScanner:
    def __init__(self, target):
        self.target = target
        self.open_ports = []
    
    def scan_ports(self):
        print(f"{Fore.YELLOW}[*] Scanning {self.target}...{Style.RESET_ALL}")
        ports = [22, 80, 443, 3306, 5432, 8080]
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    print(f"{Fore.GREEN}[+] Port {port} OPEN{Style.RESET_ALL}")
                    self.open_ports.append(port)
                sock.close()
            except:
                pass
    
    def generate_report(self):
        report = {'target': self.target, 'open_ports': self.open_ports}
        filename = f"network_scan_{self.target.replace('.', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"{Fore.GREEN}[+] Report: {filename}{Style.RESET_ALL}\n")
    
    def run(self):
        print(f"\n{Fore.CYAN}[*] === NETWORK SCAN ==={Style.RESET_ALL}\n")
        self.scan_ports()
        self.generate_report()

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3.14 scripts/network_scanner.py <target>")
        sys.exit(1)
    NetworkScanner(sys.argv[1]).run()
