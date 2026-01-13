#!/usr/bin/env python3.14
"""
CSF - Cybersecurity Framework CLI
Complete cybersecurity automation suite
"""

import sys
import argparse
from csf.core import MasterController, Dashboard, ReportGenerator
from csf.soc import LogAnalyzer
from csf.threat_intel import ThreatIntelEngine
from csf.web_security import WebSecurityScanner
from csf.network import NetworkRecon
from csf.offensive import ExploitFramework
from csf.defensive import DefenseEngine
from csf.forensics import ForensicsEngine
from colorama import Fore, Style, init

init(autoreset=True)

def main():
    parser = argparse.ArgumentParser(
        description='Cybersecurity Framework - Advanced Automation Suite'
    )
    
    parser.add_argument('--version', action='version', version='CSF 1.0.0')
    parser.add_argument('--status', action='store_true', help='Show framework status')
    parser.add_argument('--dashboard', action='store_true', help='Show dashboard')
    
    # SOC commands
    parser.add_argument('--soc-analyze', metavar='FILE', help='Analyze SOC logs')
    
    # Threat Intel
    parser.add_argument('--threat-check', metavar='IOC', help='Check threat indicator')
    
    # Web Security
    parser.add_argument('--web-scan', metavar='URL', help='Scan URL for vulnerabilities')
    
    # Network
    parser.add_argument('--network-recon', metavar='TARGET', help='Reconnaissance')
    
    # Offensive
    parser.add_argument('--generate-payload', metavar='TYPE', help='Generate payload')
    
    # Defensive
    parser.add_argument('--defense-check', action='store_true', help='Security posture')
    
    # Forensics
    parser.add_argument('--forensics', metavar='LOG', help='Forensic analysis')
    
    args = parser.parse_args()
    
    controller = MasterController()
    
    if args.status:
        controller.print_banner()
        print(controller.get_system_status())
    elif args.dashboard:
        dashboard = Dashboard(controller)
        print(dashboard.render_dashboard())
    elif args.soc_analyze:
        soc = LogAnalyzer()
        print(f"[*] Analyzing: {args.soc_analyze}")
    elif args.threat_check:
        engine = ThreatIntelEngine()
        result = engine.analyze_threat(args.threat_check)
        print(result)
    elif args.web_scan:
        scanner = WebSecurityScanner()
        result = scanner.scan_url(args.web_scan)
        print(result)
    elif args.network_recon:
        recon = NetworkRecon(args.network_recon)
        print(recon.run_full_recon())
    elif args.defense_check:
        defense = DefenseEngine()
        print(defense.run_defense_check())
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
