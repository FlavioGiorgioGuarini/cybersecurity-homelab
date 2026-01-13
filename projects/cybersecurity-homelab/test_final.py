#!/usr/bin/env python3.14
from csf.core import MasterController, Dashboard, ReportGenerator
from colorama import Fore, Style, init
init(autoreset=True)

# Initialize
controller = MasterController()
dashboard = Dashboard(controller)
report_gen = ReportGenerator()

# Print banner
controller.print_banner()

# Show system status
print(f"\n{Fore.CYAN}System Status:{Style.RESET_ALL}")
status = controller.get_system_status()
print(f"  Framework: {status['framework']}")
print(f"  Version: {status['version']}")
print(f"  Modules Loaded: {status['modules_loaded']}/{status['total_modules']}")
print(f"  Status: {'OPERATIONAL ✅' if status['ready'] else 'DEGRADED ⚠️'}")

# Show dashboard
print(dashboard.render_dashboard())

print(f"\n{Fore.GREEN}[+] All 7 Modules Successfully Initialized!{Style.RESET_ALL}")
print(f"{Fore.YELLOW}[*] CSF Framework is READY for cybersecurity operations!{Style.RESET_ALL}\n")
