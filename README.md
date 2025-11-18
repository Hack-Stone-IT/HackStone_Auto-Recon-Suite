# HackStone Auto Recon Suite

An automated reconnaissance and vulnerability scanning tool for cybersecurity professionals.

## Features

- **Subdomain Enumeration**: Discover subdomains using various techniques.
- **Port Scanning**: Comprehensive TCP port scanning with service detection.
- **Vulnerability Scanning**: Automated vulnerability detection and analysis.
- **Web Vulnerability Scanning**: Safe active scanning for common web vulnerabilities (SQLi, XSS, LFI, RCE, Open Redirect).
- **Web Technology Detection**: Identify CMS, frameworks, servers, and other web technologies.
- **Subdomain Takeover Detection**: Check for potential subdomain takeover vulnerabilities.
- **OS Fingerprinting**: Identify operating systems running on target hosts.
- **Directory Bruteforce**: Discover hidden directories and files.
- **Screenshot Capture**: Capture screenshots of discovered web assets.
- **Report Generation**: Generate detailed HTML, PDF, and JSON reports.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/hackstone/hackstone-auto-recon.git
   cd hackstone-auto-recon
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the tool:
   ```bash
   python hackstone_auto_recon.py --target example.com
   ```

## Usage

```bash
python hackstone_auto_recon.py --target <target_domain>
```

## Requirements

- Python 3.7+
- Required Python packages (see requirements.txt)

## Disclaimer

This tool is intended for educational and authorized security testing purposes only. Use responsibly and with permission.

## License

MIT License - see LICENSE file for details.
