#!/usr/bin/env python3
"""
HackStone Auto Recon Suite - Web Technology Detection
Detect CMS, frameworks, servers, etc. from headers, cookies, JS & HTML.
"""

import requests
from bs4 import BeautifulSoup
import re

class WebTechDetector:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'HackStone-Recon/1.0'
        })

    def detect(self):
        """Detect web technologies."""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            headers = response.headers
            cookies = response.cookies

            technologies = []

            # CMS Detection
            if soup.find('meta', attrs={'name': 'generator', 'content': re.compile(r'WordPress', re.I)}):
                technologies.append('WordPress')
            if soup.find('script', src=re.compile(r'joomla', re.I)):
                technologies.append('Joomla')
            if soup.find('meta', attrs={'name': 'Generator', 'content': re.compile(r'Drupal', re.I)}):
                technologies.append('Drupal')

            # Frameworks
            if soup.find('script', src=re.compile(r'react', re.I)):
                technologies.append('React')
            if soup.find('script', src=re.compile(r'angular', re.I)):
                technologies.append('Angular')
            if soup.find('script', src=re.compile(r'vue', re.I)):
                technologies.append('Vue.js')
            if soup.find('meta', attrs={'name': 'csrf-token'}) and 'laravel' in response.text.lower():
                technologies.append('Laravel')
            if 'django' in response.text.lower():
                technologies.append('Django')

            # Web Servers
            server = headers.get('Server', '')
            if 'apache' in server.lower():
                technologies.append('Apache')
            if 'nginx' in server.lower():
                technologies.append('Nginx')
            if 'iis' in server.lower():
                technologies.append('IIS')

            # CDN/WAF
            if 'cloudflare' in headers.get('CF-RAY', '').lower() or 'cloudflare' in response.text.lower():
                technologies.append('Cloudflare')
            if 'akamai' in headers.get('Server', '').lower():
                technologies.append('Akamai')

            # JS Libraries
            if soup.find('script', src=re.compile(r'jquery', re.I)):
                technologies.append('jQuery')
            if soup.find('link', href=re.compile(r'bootstrap', re.I)):
                technologies.append('Bootstrap')

            # Analytics
            if 'google-analytics' in response.text or 'gtag' in response.text:
                technologies.append('Google Analytics')
            if 'hotjar' in response.text.lower():
                technologies.append('Hotjar')

            return list(set(technologies))  # Remove duplicates
        except:
            return []

def detect(target_url):
    """Main detect function."""
    detector = WebTechDetector(target_url)
    return detector.detect()
