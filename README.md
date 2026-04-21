<div align="center">


# HackStone Auto Recon Suite

### Automated External Reconnaissance & Security Scanning Toolkit

[![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-All%20Rights%20Reserved-red?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()
[![Made By](https://img.shields.io/badge/Made%20By-HackStone%20IT-orange?style=for-the-badge)](https://hackstone.in)

**Built for security professionals, bug bounty hunters, and pentest teams who need fast, deep recon.**

[Features](#features) · [Installation](#installation) · [Usage](#usage) · [Output](#output-structure) · [Contributing](#contributing) · [Contact](#contact)

---

</div>

## What is HackStone Auto Recon Suite?

HackStone Auto Recon Suite is a **modular, automated reconnaissance and vulnerability scanning toolkit** designed for external security assessments.

Give it a domain. It does the rest.

From subdomain discovery to full vulnerability checks — it runs everything automatically and delivers a clean, professional HTML/PDF report ready for clients or your own records.

---

## Features

| Module | Description |
|--------|-------------|
| **Subdomain Enumeration** | DNS brute force, permutation scanning, wildcard detection & takeover checks |
| **Full Port Scan** | TCP scan across all 65,535 ports with banner grabbing and service fingerprinting |
| **Web Tech Detection** | Identify CMS, frameworks, servers, CDNs, and JS libraries |
| **Directory Bruteforce** | Detect hidden paths, sensitive directories, and exposed backup files |
| **Vulnerability Tests** | Safe-mode SQLi, XSS reflection, LFI, open-redirect, and RCE indicator checks |
| **Screenshot Capture** | Headless browser snapshots of all discovered domains and endpoints |
| **Professional Reports** | Auto-generated HTML & PDF reports with HackStone branding + JSON export |
| **Modular Architecture** | Easily extend with new modules and plugins |

---

## Tech Stack

```
Language     →  Python 3.x
Networking   →  Scapy, dnspython, requests
Web Parsing  →  BeautifulSoup4
Automation   →  Selenium / Playwright
Reporting    →  Jinja2, pdfkit / reportlab
CLI          →  Rich
Performance  →  Threading / asyncio
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Hack-Stone-IT/HackStone_Auto-Recon-Suite.git

# Navigate into the directory
cd HackStone_Auto-Recon-Suite

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Basic Scan
```bash
python3 hackstone_auto_recon.py --target example.com
```

### With Options
```bash
python3 hackstone_auto_recon.py --target example.com --output my_report --threads 50
```

### All Options

| Flag | Required | Description |
|------|----------|-------------|
| `--target` | Yes | Target domain or IP address |
| `--output` | No | Custom output folder or report prefix |
| `--threads` | No | Number of threads (default: 20) |

---

## Output Structure

After a scan, all results are saved in an organized report folder:

```
/reports/
  └── example.com/
       ├── report.html       ← Full visual report
       ├── report.pdf        ← Printable PDF version
       ├── results.json      ← Raw data export
       ├── screenshots/      ← Visual captures of all endpoints
       └── logs/             ← Detailed scan logs
```

---

## Legal & Ethical Use

> **This tool is for authorized security testing only.**
>
> Only run HackStone Auto Recon Suite against systems you own or have explicit written permission to test. Unauthorized use against systems you do not own is illegal and unethical.
>
> HackStone IT takes no responsibility for misuse of this tool.

---

## Contributing

Contributions are welcome. If you find a bug, want to add a module, or improve documentation:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## Contact

<div align="center">

**HackStone IT — Cybersecurity & Advanced Pentesting**

[![Website](https://img.shields.io/badge/Website-hackstone.in-blue?style=flat-square&logo=google-chrome)](https://hackstone.in)
[![Email](https://img.shields.io/badge/Email-hackstone2025@outlook.com-red?style=flat-square&logo=microsoft-outlook)](mailto:hackstone2025@outlook.com)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dhairya%20Pithadia-blue?style=flat-square&logo=linkedin)](https://linkedin.com/in/dhairya-pithadia)

---

*Stay safe. Stay secure.*

**— HackStone IT Team**

</div>
