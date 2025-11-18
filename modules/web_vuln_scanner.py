#!/usr/bin/env python3
"""
HackStone Auto Recon Suite - Web Vulnerability Scanner (SAFE)
Performs safe, non-destructive web vulnerability tests.
"""

import requests
import re
from urllib.parse import urljoin, urlparse

class WebVulnScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'HackStone-Recon/1.0'
        })
        self.vulnerabilities = []

    def test_sql_injection(self):
        """Safe SQLi tests."""
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL --",
            "1' OR '1'='1"
        ]
        for payload in payloads:
            try:
                test_url = f"{self.target_url}?id={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                if self._check_sqli_indicators(response):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'url': test_url,
                        'payload': payload,
                        'evidence': 'Error-based or boolean mismatch detected'
                    })
            except:
                pass

    def _check_sqli_indicators(self, response):
        """Check for SQLi indicators."""
        errors = [
            'sql syntax', 'mysql_fetch', 'ORA-', 'Microsoft SQL Server',
            'PostgreSQL query failed', 'SQLite/JDBCDriver'
        ]
        for error in errors:
            if error.lower() in response.text.lower():
                return True
        # Boolean mismatch check
        original_length = len(response.text)
        try:
            false_url = f"{self.target_url}?id=1' AND 1=2 --"
            false_resp = self.session.get(false_url, timeout=self.timeout)
            if abs(len(false_resp.text) - original_length) > 100:  # Size change
                return True
        except:
            pass
        return False

    def test_xss(self):
        """Safe XSS reflection test."""
        payload = "<script>alert(1)</script>"
        try:
            test_url = f"{self.target_url}?q={payload}"
            response = self.session.get(test_url, timeout=self.timeout)
            if payload in response.text:
                self.vulnerabilities.append({
                    'type': 'XSS',
                    'url': test_url,
                    'payload': payload,
                    'evidence': 'Payload reflected in response'
                })
        except:
            pass

    def test_lfi(self):
        """Safe LFI tests."""
        payloads = [
            "../../../../etc/passwd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "../../../../../../windows/system32/drivers/etc/hosts"
        ]
        for payload in payloads:
            try:
                test_url = f"{self.target_url}?file={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                if self._check_lfi_indicators(response):
                    self.vulnerabilities.append({
                        'type': 'Local File Inclusion',
                        'url': test_url,
                        'payload': payload,
                        'evidence': 'File inclusion indicators detected'
                    })
            except:
                pass

    def _check_lfi_indicators(self, response):
        """Check for LFI indicators."""
        indicators = [
            'root:x:', 'bin/bash', 'Windows', 'system32'
        ]
        for indicator in indicators:
            if indicator in response.text:
                return True
        return False

    def test_rce(self):
        """Safe RCE indicators."""
        suspicious_params = ['cmd', 'exec', 'run', 'command', 'shell']
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            for param in suspicious_params:
                if param in response.text.lower():
                    self.vulnerabilities.append({
                        'type': 'RCE Indicator',
                        'url': self.target_url,
                        'payload': param,
                        'evidence': f'Suspicious parameter "{param}" found'
                    })
            # Check for stack traces
            if 'traceback' in response.text.lower() or 'stack trace' in response.text.lower():
                self.vulnerabilities.append({
                    'type': 'RCE Indicator',
                    'url': self.target_url,
                    'payload': 'stack trace',
                    'evidence': 'Stack trace detected in response'
                })
            # Check for debug responses
            if 'debug' in response.text.lower() and 'error' in response.text.lower():
                self.vulnerabilities.append({
                    'type': 'RCE Indicator',
                    'url': self.target_url,
                    'payload': 'debug info',
                    'evidence': 'Debug information in response'
                })
        except:
            pass

    def test_open_redirect(self):
        """Safe open redirect test."""
        redirect_params = ['url', 'next', 'redirect', 'return', 'goto']
        payload = "https://example.com"
        for param in redirect_params:
            try:
                test_url = f"{self.target_url}?{param}={payload}"
                response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if payload in location:
                        self.vulnerabilities.append({
                            'type': 'Open Redirect',
                            'url': test_url,
                            'payload': payload,
                            'evidence': f'Redirects to {location}'
                        })
            except:
                pass

    def scan(self):
        """Run all safe vuln tests."""
        self.test_sql_injection()
        self.test_xss()
        self.test_lfi()
        self.test_rce()
        self.test_open_redirect()
        return self.vulnerabilities

def scan(target_url):
    """Main scan function."""
    scanner = WebVulnScanner(target_url)
    return scanner.scan()
