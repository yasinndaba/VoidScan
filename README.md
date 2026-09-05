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

Milestone 5 — Reporting: In Progress

Milestone 6 — Testing & Quality: In Progress

## Current Capabilities

### Core Framework

- Target validation
- Target management
- Application configuration
- Structured logging
- Error handling
- Scan profiles

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
- Automatic report timestamps
- Scanner result serialization
- Nmap scan report generation
- Report storage in `~/.voidscan/reports/`

## Architecture

VoidScan separates scanning logic from presentation and reporting:

Target → Validation → Scan Profile → Scanner → Structured Result → Report

Scanner modules are responsible for executing security tools and returning structured results. Reporting is handled independently so the same scanner results can later be used for terminal, JSON, and HTML reports.

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
│   └── reports/
│       ├── __init__.py
│       └── reporter.py
│
├── tests/
├── docs/
├── screenshots/
├── .github/
├── main.py
├── pyproject.toml
├── README.md
├── CHANGELOG.md
└── ROADMAP.md
