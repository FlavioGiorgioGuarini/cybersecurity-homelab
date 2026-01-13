#!/usr/bin/env python3.14
"""Crypto Tool"""

from Crypto.Hash import SHA256, MD5
from colorama import Fore, Style

class CryptoTool:
    @staticmethod
    def hash_sha256(text):
        h = SHA256.new()
        h.update(text.encode())
        return h.hexdigest()
    
    @staticmethod
    def hash_md5(text):
        h = MD5.new()
        h.update(text.encode())
        return h.hexdigest()

if __name__ == "__main__":
    import sys
    password = sys.argv[1] if len(sys.argv) > 1 else "MySecretPassword123!"
    print(f"\n{Fore.CYAN}[*] Crypto Tool{Style.RESET_ALL}\n")
    print(f"{Fore.YELLOW}Password: {password}{Style.RESET_ALL}\n")
    print(f"{Fore.GREEN}SHA256: {CryptoTool.hash_sha256(password)}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}MD5:    {CryptoTool.hash_md5(password)}{Style.RESET_ALL}\n")
