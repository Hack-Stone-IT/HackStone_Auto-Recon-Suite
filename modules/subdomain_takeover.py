#!/usr/bin/env python3
"""
HackStone Auto Recon Suite - Subdomain Takeover Detection
Checks for subdomain takeover vulnerabilities.
"""

import dns.resolver
import requests
from urllib.parse import urlparse

class SubdomainTakeoverScanner:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.takeover_indicators = {
            'github.io': 'GitHub Pages',
            'herokuapp.com': 'Heroku',
            's3.amazonaws.com': 'AWS S3',
            'azurewebsites.net': 'Azure',
            'firebaseapp.com': 'Firebase',
            '000webhostapp.com': '000webhost',
            'surge.sh': 'Surge',
            'netlify.com': 'Netlify',
            'vercel.app': 'Vercel'
        }

    def check_takeover(self, subdomain):
        """Check if subdomain is vulnerable to takeover."""
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).rstrip('.')
                for vuln_domain, service in self.takeover_indicators.items():
                    if vuln_domain in cname:
                        # Verify if the service is not configured
                        if self._verify_takeover(cname, service):
                            return {
                                'subdomain': subdomain,
                                'cname': cname,
                                'service': service,
                                'vulnerable': True
                            }
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            pass
        return None

    def _verify_takeover(self, cname, service):
        """Verify if the CNAME points to an unconfigured service."""
        try:
            if service == 'GitHub Pages':
                response = requests.get(f'https://{cname}', timeout=self.timeout)
                if 'There isn\'t a GitHub Pages site here.' in response.text:
                    return True
            elif service == 'Heroku':
                response = requests.get(f'https://{cname}', timeout=self.timeout)
                if 'No such app' in response.text or response.status_code == 404:
                    return True
            elif service == 'AWS S3':
                response = requests.get(f'https://{cname}', timeout=self.timeout)
                if 'NoSuchBucket' in response.text or 'The specified bucket does not exist' in response.text:
                    return True
            # Add more verifications for other services as needed
            return False
        except:
            return False

    def scan(self, subdomains):
        """Scan list of subdomains for takeover vulnerabilities."""
        results = []
        for subdomain in subdomains:
            result = self.check_takeover(subdomain)
            if result:
                results.append(result)
        return results

def scan(subdomains):
    """Main scan function."""
    scanner = SubdomainTakeoverScanner()
    return scanner.scan(subdomains)
