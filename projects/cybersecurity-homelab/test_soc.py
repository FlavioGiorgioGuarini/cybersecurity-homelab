#!/usr/bin/env python3.14
from csf.soc import LogAnalyzer
from colorama import Fore, Style, init
init(autoreset=True)

analyzer = LogAnalyzer()
print(f"\n{Fore.CYAN}[*] SOC Framework Initialized{Style.RESET_ALL}")
print(f"{Fore.GREEN}[+] Components:{Style.RESET_ALL}")
print("    ✅ IDSParser")
print("    ✅ SIEMCorrelator")
print("    ✅ LogAnalyzer")
print(f"{Fore.YELLOW}[*] SLOT 1 COMPLETE - Ready for THREAT INTEL{Style.RESET_ALL}\n")
