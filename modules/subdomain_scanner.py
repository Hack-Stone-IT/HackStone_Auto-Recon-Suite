"""
HackStone Auto Recon Suite - Subdomain Scanner Module
Performs DNS brute force, resolution, permutation, and wildcard detection.
Developed by HackStone Cybersecurity Company.
"""

import dns.resolver
import dns.exception
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

class SubdomainResult:
    def __init__(self, name, ip=None):
        self.name = name
        self.ip = ip

def resolve_subdomain(subdomain, target):
    """Resolve a single subdomain."""
    try:
        answers = dns.resolver.resolve(f"{subdomain}.{target}", 'A')
        ip = answers[0].address
        return SubdomainResult(f"{subdomain}.{target}", ip)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None

def check_wildcard(target):
    """Check for wildcard DNS."""
    try:
        answers = dns.resolver.resolve(f"randomstring123.{target}", 'A')
        return answers[0].address
    except:
        return None

def generate_permutations(domain):
    """Generate subdomain permutations."""
    prefixes = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop', 'app']
    return [f"{prefix}.{domain}" for prefix in prefixes]

def brute_force_subdomains(target, wordlist=None):
    """Perform DNS brute force."""
    if wordlist is None:
        wordlist = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop', 'app', 'ns1', 'ns2']

    wildcard_ip = check_wildcard(target)
    results = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(resolve_subdomain, sub, target) for sub in wordlist]
        for future in as_completed(futures):
            result = future.result()
            if result and (not wildcard_ip or result.ip != wildcard_ip):
                results.append(result)

    return results

def scan(target):
    """Main subdomain scanning function."""
    print("Scanning subdomains...")

    # Brute force
    brute_results = brute_force_subdomains(target)

    # Permutations
    perm_results = []
    for perm in generate_permutations(target):
        result = resolve_subdomain(perm.split('.')[0], target)
        if result:
            perm_results.append(result)

    all_results = brute_results + perm_results
    unique_results = {res.name: res for res in all_results}.values()

    print(f"Found {len(unique_results)} subdomains")
    return list(unique_results)
