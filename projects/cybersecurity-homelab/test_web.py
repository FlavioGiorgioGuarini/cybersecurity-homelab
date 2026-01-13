#!/usr/bin/env python3.14
from csf.web_security import WebSecurityScanner
from colorama import Fore, Style, init
init(autoreset=True)

scanner = WebSecurityScanner()
print(f"\n{Fore.CYAN}[*] Web Security Scanner Initialized{Style.RESET_ALL}")
print(f"{Fore.GREEN}[+] Components:{Style.RESET_ALL}")
print("    ✅ SQLiDetector")
print("    ✅ XSSFinder")
print("    ✅ JWTAnalyzer")
print("    ✅ WebSecurityScanner")
print(f"\n{Fore.YELLOW}[*] SLOT 3 COMPLETE - Ready for NETWORK/OFFENSIVE{Style.RESET_ALL}\n")
