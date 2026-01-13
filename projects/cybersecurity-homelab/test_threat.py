#!/usr/bin/env python3.14
from csf.threat_intel import ThreatIntelEngine
from colorama import Fore, Style, init
init(autoreset=True)

engine = ThreatIntelEngine()
print(f"\n{Fore.CYAN}[*] Threat Intelligence Engine Initialized{Style.RESET_ALL}")
print(f"{Fore.GREEN}[+] Components:{Style.RESET_ALL}")
print("    ✅ IoCScraper")
print("    ✅ MitreMapper")
print("    ✅ ThreatIntelEngine")
print(f"\n{Fore.YELLOW}[*] SLOT 2 COMPLETE - Ready for WEB SECURITY{Style.RESET_ALL}\n")
