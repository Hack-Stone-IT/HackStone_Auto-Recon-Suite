"""
HackStone Auto Recon Suite - Vulnerability Scanner Module
Detects web, network, and TLS vulnerabilities.
Developed by HackStone Cybersecurity Company.
"""

import requests
import ssl
import socket
from urllib.parse import urljoin

class Vulnerability:
    def __init__(self, title, severity, description, recommendation):
        self.title = title
        self.severity = severity
        self.description = description
        self.recommendation = recommendation

def check_security_headers(url):
    """Check for missing security headers."""
    vulns = []
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
                           'Strict-Transport-Security', 'Content-Security-Policy']

        for header in security_headers:
            if header not in headers:
                vulns.append(Vulnerability(
                    f"Missing {header} Header",
                    "Medium",
                    f"The {header} security header is missing from the HTTP response.",
                    f"Implement the {header} header to enhance security."
                ))
    except:
        pass
    return vulns

def check_open_directories(url):
    """Check for open directory indexing."""
    vulns = []
    common_dirs = ['/admin/', '/backup/', '/config/', '/db/', '/logs/']
    for dir_path in common_dirs:
        try:
            full_url = urljoin(url, dir_path)
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200 and 'index of' in response.text.lower():
                vulns.append(Vulnerability(
                    "Open Directory Listing",
                    "High",
                    f"Directory {dir_path} is open and allows directory listing.",
                    "Disable directory listing or restrict access."
                ))
        except:
            pass
    return vulns

def check_tls_certificate(host):
    """Check TLS certificate validity."""
    vulns = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # Check expiration (simplified)
                if 'notAfter' in cert:
                    # In real implementation, parse date and check if expired
                    pass
                if cert.get('issuer') and 'self' in str(cert['issuer']).lower():
                    vulns.append(Vulnerability(
                        "Self-Signed Certificate",
                        "Medium",
                        "The server is using a self-signed SSL certificate.",
                        "Replace with a certificate from a trusted CA."
                    ))
    except:
        pass
    return vulns

def check_sensitive_ports(open_ports):
    """Check for open sensitive ports."""
    vulns = []
    sensitive_ports = {21: 'FTP', 23: 'Telnet', 3389: 'RDP'}
    for port in open_ports:
        if port.number in sensitive_ports:
            vulns.append(Vulnerability(
                f"Open {sensitive_ports[port.number]} Port",
                "High",
                f"Port {port.number} ({sensitive_ports[port.number]}) is open and may be vulnerable.",
                "Restrict access or use secure alternatives."
            ))
    return vulns

def scan(target, open_ports):
    """Main vulnerability scanning function."""
    print("Scanning for vulnerabilities...")

    vulns = []

    # Web vulnerabilities
    url = f"http://{target}"
    vulns.extend(check_security_headers(url))
    vulns.extend(check_open_directories(url))

    # TLS checks
    vulns.extend(check_tls_certificate(target))

    # Network vulnerabilities
    vulns.extend(check_sensitive_ports(open_ports))

    print(f"Found {len(vulns)} vulnerabilities")
    return vulns
