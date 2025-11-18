# HackStone Auto Recon Suite  
Automated External Reconnaissance & Security Scanning Toolkit

---

## Overview  
HackStone Auto Recon Suite is a modular, automated reconnaissance and vulnerability scanning tool designed for external security assessments. It is built for security professionals, bug bounty hunters, and pentesting teams who want to gain rapid insights into the exposure of public-facing assets.

---

## Key Features  
- **Subdomain Enumeration** – DNS brute force, permutation scanning, wildcard detection & takeover checks  
- **Full TCP Port Scan (1–65535)** – Threaded scanning, banner grabbing, intelligent service detection  
- **Web Technology Detection** – Identify CMS, frameworks, servers, CDNs, JS libraries  
- **Directory & File Bruteforce** – Detect sensitive paths, hidden directories, backup files  
- **Active Web Vulnerability Tests (Safe Mode)** – SQLi (non-destructive), XSS reflection, LFI checks, open-redirect tests, RCE indicators  
- **Screenshot Capture** – Headless browser snapshots of domains, subdomains & endpoints  
- **Professional Reporting** – Generates HTML & PDF reports + JSON data export with HackStone branding  
- **Modular & Extensible** – Designed to be extended with additional modules and plugins  

---

## Tech Stack  
- Python 3.x  
- `requests`, `dnspython`, `scapy`  
- `beautifulsoup4`, `selenium` / `playwright`  
- `jinja2` for HTML templates  
- `pdfkit` / `reportlab` for PDF generation  
- `rich` for CLI interface  
- Threading / asyncio for performance  

---

## Installation  
```bash
git clone https://github.com/Hack-Stone-IT/HackStone_Auto-Recon-Suite.git  
cd HackStone_Auto-Recon-Suite  
pip install -r requirements.txt  
```

## Usage
```bash
python3 hackstone_auto_recon.py --target example.com
```
Options:

--target : Target domain or IP

--output : (Optional) Output folder or report prefix

--threads : (Optional) Number of threads to use

## Output Structure
```bash
/reports/
  └── example.com/
       ├── report.html  
       ├── report.pdf  
       ├── results.json  
       ├── screenshots/  
       └── logs/
```
## License & Terms

All Rights Reserved — HackStone IT
This tool is provided for authorized testing only.
Do not use it against unauthorized targets.

## Contributing

We welcome contributions! Please feel free to open issues or submit pull requests for improvements, additional modules, or bug fixes.

## Contact

HackStone IT – Cybersecurity & Advanced Pentesting
Website: https://hackstone.in
Email: hackstone2025@outlook.com

## Stay safe. Stay secure.
– HackStone IT Team
