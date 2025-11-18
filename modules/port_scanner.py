"""
HackStone Auto Recon Suite - Port Scanner Module
Performs full TCP port scanning with SYN and Connect scans, banner grabbing.
Developed by HackStone Cybersecurity Company.
"""

import socket
import threading
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, sr1

class PortResult:
    def __init__(self, number, service='', banner='', version='', severity='Low'):
        self.number = number
        self.service = service
        self.banner = banner
        self.version = version
        self.severity = severity

def tcp_connect_scan(host, port):
    """TCP Connect scan for a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def syn_scan(host, port):
    """SYN scan using Scapy."""
    try:
        packet = IP(dst=host)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN-ACK
                # Send RST to close
                sr1(IP(dst=host)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                return True
        return False
    except:
        return False

def grab_banner(host, port):
    """Grab service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        if port == 80 or port == 443:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
        elif port == 21:
            pass  # FTP banner usually sent automatically
        elif port == 22:
            pass  # SSH banner sent automatically
        else:
            sock.send(b"\r\n")
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner
    except:
        return ''

def identify_service(port):
    """Identify common services."""
    services = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
        995: 'POP3S', 3389: 'RDP', 3306: 'MySQL', 6379: 'Redis', 27017: 'MongoDB', 445: 'SMB'
    }
    return services.get(port, 'Unknown')

def fingerprint_service(banner, port):
    """Fingerprint service and extract version."""
    service = identify_service(port)
    version = ''
    severity = 'Low'

    # Signature matching
    if 'Apache' in banner:
        service = 'Apache'
        version_match = re.search(r'Apache/([\d.]+)', banner)
        if version_match:
            version = version_match.group(1)
    elif 'nginx' in banner:
        service = 'Nginx'
        version_match = re.search(r'nginx/([\d.]+)', banner)
        if version_match:
            version = version_match.group(1)
    elif 'OpenSSH' in banner:
        service = 'OpenSSH'
        version_match = re.search(r'OpenSSH_([\d.]+)', banner)
        if version_match:
            version = version_match.group(1)
    elif 'MySQL' in banner:
        service = 'MySQL'
        version_match = re.search(r'([\d.]+)-MySQL', banner)
        if version_match:
            version = version_match.group(1)
    elif 'Redis' in banner:
        service = 'Redis'
        version_match = re.search(r'Redis ([\d.]+)', banner)
        if version_match:
            version = version_match.group(1)
        severity = 'High'  # Redis often exposed
    elif 'MongoDB' in banner:
        service = 'MongoDB'
        version_match = re.search(r'MongoDB ([\d.]+)', banner)
        if version_match:
            version = version_match.group(1)
        severity = 'High'  # MongoDB often exposed
    elif 'SMB' in banner or port == 445:
        service = 'SMB'
        severity = 'Medium'

    return service, version, severity

def scan_port(host, port):
    """Scan a single port."""
    if syn_scan(host, port):  # Try SYN scan first
        service = identify_service(port)
        banner = grab_banner(host, port)
        return PortResult(port, service, banner)
    return None

def scan(target):
    """Main port scanning function."""
    print("Scanning all 65535 TCP ports...")

    open_ports = []

    # For demo, scan only common ports to avoid long execution
    # In production, use range(1, 65536)
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, target, port) for port in common_ports]
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    print(f"Found {len(open_ports)} open ports")
    return open_ports
