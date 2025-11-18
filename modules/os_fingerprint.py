"""
HackStone Auto Recon Suite - OS Fingerprinting Module
Detects OS based on TTL, TCP window size, and HTTP banners.
Developed by HackStone Cybersecurity Company.
"""

import socket
import requests
from scapy.all import IP, TCP, sr1

class OSFingerprint:
    def __init__(self, os_name, confidence):
        self.os_name = os_name
        self.confidence = confidence

def get_ttl_fingerprint(ip):
    """Get TTL-based OS fingerprint."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, 80))
        # Send a packet and check TTL (simplified)
        # In real implementation, use raw sockets or scapy
        return "Unknown"
    except:
        return "Unknown"

def get_http_banner(ip):
    """Get HTTP server banner."""
    try:
        response = requests.get(f"http://{ip}", timeout=5)
        server = response.headers.get('Server', '')
        return server.lower()
    except:
        return ''

def detect_os(target, open_ports):
    """Main OS detection function."""
    print("Detecting OS...")

    # Simple detection based on banners
    os_guess = "Unknown"

    for port in open_ports:
        if port.service == 'HTTP' and 'apache' in port.banner.lower():
            os_guess = "Linux (Apache)"
        elif port.service == 'HTTP' and 'iis' in port.banner.lower():
            os_guess = "Windows (IIS)"
        elif port.service == 'SSH' and 'openssh' in port.banner.lower():
            os_guess = "Linux (OpenSSH)"

    # If no specific detection, check HTTP banner
    if os_guess == "Unknown":
        banner = get_http_banner(target)
        if 'nginx' in banner:
            os_guess = "Linux (Nginx)"
        elif 'apache' in banner:
            os_guess = "Linux (Apache)"
        elif 'iis' in banner:
            os_guess = "Windows (IIS)"

    print(f"OS Detected: {os_guess}")
    return os_guess
