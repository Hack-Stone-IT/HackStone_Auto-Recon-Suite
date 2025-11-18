"""
HackStone Auto Recon Suite - Directory & File Bruteforce Module
Performs multi-threaded directory and file bruteforce scanning, detecting status codes, directory listings, and sensitive files.
Developed by HackStone Cybersecurity Company.
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common wordlist for directories and files
COMMON_PATHS = [
    'admin', 'admin/', 'administrator', 'administrator/', 'login', 'login/', 'dashboard', 'dashboard/',
    'wp-admin', 'wp-admin/', 'phpmyadmin', 'phpmyadmin/', 'backup', 'backup/', 'backups', 'backups/',
    'config', 'config/', 'configuration', 'configuration/', 'db', 'db/', 'database', 'database/',
    'uploads', 'uploads/', 'files', 'files/', 'images', 'images/', 'css', 'css/', 'js', 'js/',
    'api', 'api/', 'v1', 'v1/', 'v2', 'v2/', 'test', 'test/', 'dev', 'dev/', 'staging', 'staging/',
    '.env', '.git', '.gitignore', 'backup.zip', 'db.sql', 'phpinfo.php', 'info.php', 'server-status',
    'server-info', 'php.ini', 'web.config', '.htaccess', '.htpasswd', 'readme.txt', 'changelog.txt'
]

SENSITIVE_FILES = ['.env', '.git', 'backup.zip', 'db.sql', 'phpinfo.php']

def check_path(target, path):
    """Check a single path on the target."""
    urls = [f"http://{target}/{path}", f"https://{target}/{path}"]
    results = []

    for url in urls:
        try:
            response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
            status = response.status_code
            if status in [200, 301, 302, 403]:
                is_directory = path.endswith('/') or '/' in path[:-1]  # Simple heuristic
                is_listing = 'index of' in response.text.lower()
                is_sensitive = any(sens in path for sens in SENSITIVE_FILES)
                result = {
                    'path': path,
                    'url': url,
                    'status': status,
                    'type': 'directory' if is_directory else 'file',
                    'listing': is_listing,
                    'sensitive': is_sensitive
                }
                results.append(result)
        except requests.RequestException:
            pass  # Ignore errors

    return results

def scan(target):
    """Main directory and file bruteforce function."""
    print("Performing directory and file bruteforce scan...")

    found_items = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_path, target, path) for path in COMMON_PATHS]
        for future in as_completed(futures):
            results = future.result()
            found_items.extend(results)

    print(f"Found {len(found_items)} interesting paths")
    return found_items
