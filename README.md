# VoidScan

VoidScan is a modular Python-based reconnaissance and security assessment toolkit designed for authorized security testing, cybersecurity laboratories, and defensive security research.

The project is being developed as a cybersecurity portfolio project to demonstrate practical Python development, security automation, reconnaissance, security tooling integration, testing, documentation, and secure software development practices.

## Current Status

Version: 0.1.0

Milestone 0 — Project Foundation: Complete

Milestone 1 — Core Framework: Complete

Milestone 2 — Nmap Engine: Complete

Milestone 3 — Network Discovery: Complete

Milestone 4 — Web Reconnaissance: Complete

Milestone 5 — Reporting: Complete

Milestone 6 — Testing & Quality: In Progress

## Current Capabilities

### Core Framework

- Target validation for IP addresses, hostnames, and HTTP(S) URLs
- Target management
- Application configuration
- Structured logging with an in-app log viewer
- Startup dependency checks
- Read-only settings and external tool status panel
- Error handling
- Scan profiles with non-root fallbacks

### Network Reconnaissance

- Nmap network scanning
- Quick, standard, and full scan profiles
- Safe subprocess execution
- Nmap timeout handling
- Live host discovery
- CIDR network validation

### Web Reconnaissance

- Subdomain enumeration
- Subfinder integration
- Amass integration
- Directory enumeration
- FFUF integration
- DIRB integration
- URL validation
- Wordlist validation

### IP Information

- IPv4 and IPv6 information
- Private address detection
- Loopback detection
- Reserved address detection
- Multicast detection
- Reverse DNS lookup
- Hostname resolution

### System Monitoring

- Hostname information
- Operating system information
- Kernel information
- CPU information
- Memory usage
- Disk usage
- System uptime

### Reporting

- Standardized report structure
- JSON report generation
- HTML report generation
- Terminal report summaries
- Unique timestamped JSON and HTML report filenames
- Scanner result serialization
- Nmap scan report generation
- Structured security findings with severity levels
- Findings analyzers for Nmap, host discovery, subdomains, directories, and IP information
- Risk-based severity for exposed services (Telnet, SMB, RDP, databases, and more)
- Findings included in JSON and HTML reports
- Report storage under `~/.voidscan/reports/`

## Architecture

VoidScan separates scanning logic from presentation and reporting:

Target → Validation → Scan Profile → Scanner → Structured Result → Report

Scanner modules are responsible for executing security tools and returning structured results. Reporting is handled independently so the same scanner results can later be used for terminal, JSON, and HTML reports.

## Installation

### Prerequisites

- Python 3.10 or newer
- Linux (host discovery uses the system `ping` command)
- External tools on your `PATH`: `nmap`, `ffuf`, `dirb`, `subfinder`, and `amass`

Install the external tools with your distribution's package manager or from
their upstream releases. Missing tools are reported at startup and in the
Settings panel.

### Setup

```bash
git clone https://github.com/yasinndaba/VoidScan.git
cd VoidScan
python -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
```

## Usage

Start the interactive menu with either command:

```bash
python main.py
```

```bash
voidscan
```

The menu provides:

1. Network Scan — Nmap quick, standard, and full profiles
2. Live Host Discovery — concurrent ICMP discovery for a CIDR network
3. Subdomain Enumeration — Subfinder or Amass
4. Directory Enumeration — FFUF or DIRB
5. IP Information — address classification and reverse DNS
6. System Monitor — local host, CPU, memory, disk, and uptime
7. Target Manager — add, list, remove, and clear targets
8. View Logs — recent entries from `~/.voidscan/logs/voidscan.log`
9. Settings — configuration paths and external tool status

### Target types

- Target Manager accepts IP addresses, hostnames (including `localhost`),
  and HTTP(S) URLs.
- Network Scan and IP Information use the host portion of a URL target.
- Directory Enumeration accepts a URL or a bare host; bare hosts default to
  `http://`.
- Live Host Discovery asks for a CIDR network directly; targets do not need
  to be saved first.

### Scan profiles

- **Quick** scans the top 100 ports.
- **Standard** adds service detection.
- **Full** adds service detection and default scripts, with OS detection
  when the process has root privileges.
- Without root, VoidScan automatically uses a TCP connect scan (`-sT`)
  instead of a SYN scan (`-sS`) so every profile still works.

## Logs and Reports

Reports are written to `~/.voidscan/reports/` with unique timestamped names,
for example `network_scan_20261025_120906_774999.json`. Every report includes
a `findings` array, even when nothing was found.

Application logs are written to `~/.voidscan/logs/voidscan.log` and can be
read from the main menu with **View Logs**.

## Limits and Safety

- Host discovery is capped at 4096 hosts per scan to prevent accidental
  large-network scans. It runs concurrently with a bounded worker pool.
- Large terminal result tables are truncated to the first 50 rows. The full
  results are always included in saved reports.
- Amass passive enumeration can take several minutes; Subfinder is faster.
- Use VoidScan only against systems you are authorized to test.

## Testing

```bash
pytest -q
```

## Roadmap

The prioritized plan for reliability, quality, and the v1.0 release is in
[ROADMAP.md](ROADMAP.md).

## Project Structure

```text
VoidScan/
├── voidscan/
│   ├── __init__.py
│   ├── cli.py
│   ├── menu.py
│   ├── config.py
│   ├── logger.py
│   ├── targets.py
│   ├── validators.py
│   │
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── nmap.py
│   │   ├── discovery.py
│   │   ├── subdomains.py
│   │   ├── directories.py
│   │   ├── ip_info.py
│   │   └── system_monitor.py
│   │
│   ├── findings.py
│   ├── findings_nmap.py
│   ├── findings_discovery.py
│   ├── findings_subdomains.py
│   ├── findings_directories.py
│   ├── findings_ip_info.py
│   │
│   ├── reporter.py
│   ├── html_reporter.py
│   └── dependencies.py
│
├── tests/
├── docs/
├── screenshots/
├── main.py
├── pyproject.toml
├── README.md
├── CHANGELOG.md
└── ROADMAP.md
