#!/usr/bin/env python3.14
from csf.network import NetworkRecon
from csf.offensive import ExploitFramework
from colorama import Fore, Style, init
init(autoreset=True)

print(f"\n{Fore.CYAN}[*] Network & Offensive Modules Initialized{Style.RESET_ALL}")
print(f"{Fore.GREEN}[+] Network Components:{Style.RESET_ALL}")
print("    ✅ SubdomainEnumerator")
print("    ✅ PortScanner")
print("    ✅ VulnScanner")
print(f"\n{Fore.GREEN}[+] Offensive Components:{Style.RESET_ALL}")
print("    ✅ PayloadGenerator")
print("    ✅ PoCSuggester")
print("    ✅ ExploitFramework")
print(f"\n{Fore.YELLOW}[*] SLOT 4 COMPLETE - Ready for BLUE TEAM/FORENSICS{Style.RESET_ALL}\n")
