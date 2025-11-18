#!/usr/bin/env python3
"""
HackStone Auto Recon Suite - Main Entry Point
A comprehensive black-box automated reconnaissance and vulnerability scanner.
Developed by HackStone Cybersecurity Company.

Usage: python hackstone_auto_recon.py --target example.com
"""

import argparse
import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from modules import subdomain_scanner, port_scanner, vuln_scanner, os_fingerprint, dir_bruteforce, report_generator, web_vuln_scanner, web_tech_detector, subdomain_takeover, screenshot_capture

# HackStone Branding
HACKSTONE_BANNER = """
██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗
██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝
███████║███████║██║     █████╔╝ ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗
██╔══██║██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
██║  ██║██║  ██║╚██████╗██║  ██╗███████║   ██║   ╚██████╔╝██║ ╚████║███████╗
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝

                    AUTO RECON SUITE v1.0
                    Developed by HackStone Cybersecurity
"""

console = Console()

def print_banner():
    """Print HackStone branded CLI banner."""
    console.print(Panel.fit(HACKSTONE_BANNER, style="bold cyan", border_style="blue"))

def validate_target(target):
    """Basic target validation."""
    if not target:
        console.print("[red]Error: Target domain/IP required.[/red]")
        sys.exit(1)
    # Add more validation if needed
    return target

def main():
    parser = argparse.ArgumentParser(description="HackStone Auto Recon Suite")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    args = parser.parse_args()

    print_banner()

    target = validate_target(args.target)
    console.print(f"[cyan]Target: {target}[/cyan]")

    # Tool Flow as per requirements
    console.print("[blue]Step 1: Auto Host Discovery[/blue]")
    # Placeholder for host discovery

    console.print("[blue]Step 2: Auto Subdomain Scan[/blue]")
    subdomains = subdomain_scanner.scan(target)

    console.print("[blue]Step 3: Auto Full-Port Scan[/blue]")
    open_ports = port_scanner.scan(target)

    console.print("[blue]Step 4: Auto Service & Banner Detection[/blue]")
    # Integrated in port_scanner

    console.print("[blue]Step 5: Auto Vulnerability Analysis[/blue]")
    vulnerabilities = vuln_scanner.scan(target, open_ports)

    console.print("[blue]Step 6: OS Fingerprinting[/blue]")
    os_info = os_fingerprint.detect_os(target, open_ports)

    console.print("[blue]Step 7: Directory & File Bruteforce[/blue]")
    dir_results = dir_bruteforce.scan(target)

    console.print("[blue]Step 8: Screenshot Capture[/blue]")
    screenshots = screenshot_capture.scan(target, subdomains)

    console.print("[blue]Step 9: Web Vulnerability Scanning[/blue]")
    web_vulns = web_vuln_scanner.scan(f"https://{target}")

    console.print("[blue]Step 10: Web Technology Detection[/blue]")
    web_tech = web_tech_detector.detect(f"https://{target}")

    console.print("[blue]Step 11: Subdomain Takeover Detection[/blue]")
    takeover_results = subdomain_takeover.scan(subdomains)

    console.print("[blue]Step 12: Generate Reports[/blue]")
    report_data = {
        'target': target,
        'subdomains': subdomains,
        'open_ports': open_ports,
        'vulnerabilities': vulnerabilities,
        'os_info': os_info,
        'dir_bruteforce': dir_results,
        'screenshots': screenshots,
        'web_vulnerabilities': web_vulns,
        'web_technologies': web_tech,
        'subdomain_takeover': takeover_results
    }
    report_generator.generate_html(report_data)
    report_generator.generate_pdf(report_data)
    report_generator.save_json(report_data)

    console.print("[blue]Step 12: Print Summary[/blue]")
    console.print(f"Subdomains found: {len(subdomains)}")
    console.print(f"Open ports: {len(open_ports)}")
    console.print(f"Vulnerabilities: {len(vulnerabilities)}")
    console.print(f"Web Vulnerabilities: {len(web_vulns)}")
    console.print(f"Web Technologies: {len(web_tech)}")
    console.print(f"OS Detected: {os_info}")
    console.print(f"Directories/Files found: {len(dir_results)}")
    console.print(f"Screenshots captured: {len(screenshots)}")
    console.print(f"Subdomain Takeover Checks: {len(takeover_results)}")

    console.print("[green]Scan Complete! Reports saved in /reports/{target}/[/green]")

if __name__ == "__main__":
    main()
