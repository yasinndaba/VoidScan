# VoidScan

VoidScan is a modular Python-based reconnaissance and security assessment toolkit designed for authorized security testing, cybersecurity laboratories, and defensive security research.

The project is being developed as a cybersecurity portfolio project to demonstrate practical Python development, security automation, reconnaissance, security tooling integration, testing, documentation, and secure software development practices.

## Current Status

Version: 0.2.0

Release v0.2 — Reliable scans: Complete

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
- TOML configuration file with environment and command-line overrides
- Scans run on a worker thread with live progress and an elapsed-time heartbeat
- Cancellable scans: Ctrl+C offers **cancel** or **exit** and terminates child processes
- Structured logging with an in-app log viewer
- Startup dependency checks and configuration warnings
- Settings panel with paths, timeouts, discovery limits, and tool status
- Error handling
- Scan profiles with non-root fallbacks

### Network Reconnaissance

- Nmap network scanning
- Quick, standard, and full scan profiles
- Safe subprocess execution
- Configurable Nmap timeout
- Live host discovery
- CIDR network validation
- Configurable host limit, worker count, and ping timeout

### Web Reconnaissance

- Subdomain enumeration
- Subfinder integration
- Amass integration, including partial results on timeout
- Optional Subfinder retry after an Amass timeout
- Directory enumeration
- FFUF integration
- DIRB integration
- Configurable FFUF and DIRB timeouts
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

- Standardized report structure with `schema_version`
- JSON report generation
- HTML report generation
- Terminal report summaries
- Unique timestamped JSON and HTML report filenames
- Scanner result serialization
- Nmap scan report generation
- Structured security findings with severity levels
- Findings analyzers for Nmap, host discovery, subdomains, directories, and IP information
- Risk-based severity for exposed services (Telnet, SMB, RDP, databases, and more)
- Findings deduplication that merges all unique evidence
- Findings included in JSON and HTML reports
- Consistent empty, timeout, missing-tool, and invalid-input panels
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
9. Settings — paths, per-tool timeouts, discovery limits, and tool status

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

## Configuration

VoidScan reads `~/.voidscan/config.toml` at startup. Missing settings use safe
defaults, and invalid values produce a startup warning while the remaining
settings still load. A commented starting point is available in
[`config.example.toml`](config.example.toml).

```toml
[paths]
data_dir = "~/.voidscan"
log_dir = "~/.voidscan/logs"
report_dir = "~/.voidscan/reports"
target_file = "~/.voidscan/targets.txt"

[timeouts]
nmap = 300
ffuf = 300
dirb = 300
subfinder = 300
amass = 900

[discovery]
max_hosts = 4096
workers = 32
ping_timeout = 1
```

Settings are applied in this order, with later sources winning:

1. Built-in defaults
2. `~/.voidscan/config.toml`
3. `VOIDSCAN_*` environment variables
4. Command-line flags

Environment overrides include `VOIDSCAN_CONFIG`, `VOIDSCAN_DATA_DIR`,
`VOIDSCAN_NMAP_TIMEOUT`, `VOIDSCAN_MAX_HOSTS`, and
`VOIDSCAN_DISCOVERY_WORKERS`. Run `voidscan --help` for the available flags:

```bash
voidscan --config ./lab.toml --data-dir ./lab-data
```

Restart VoidScan after editing the configuration file. The Settings panel
shows the active file and effective values.

### Cancelling a scan

Long-running scans show elapsed time and progress. Press **Ctrl+C** while a
scan is running to choose **cancel** (stop the scan and stay in VoidScan) or
**exit** (leave VoidScan). Active child processes are terminated promptly, and
cancelled scans do not write a report.

## Logs and Reports

Reports are written to `~/.voidscan/reports/` with unique timestamped names,
for example `network_scan_20261025_120906_774999.json`. Every report includes
a `schema_version`, the VoidScan `version`, and a `findings` array, even when
nothing was found.

Application logs are written to `~/.voidscan/logs/voidscan.log` and can be
read from the main menu with **View Logs**.

## Limits and Safety

- Host discovery is capped at 4096 hosts per scan by default to prevent
  accidental large-network scans. The cap, worker count, and ping timeout are
  configurable.
- Per-tool timeouts are configurable. Nmap, FFUF, DIRB, and Subfinder default
  to 300 seconds; Amass defaults to 900 seconds.
- When Amass times out, its partial results are kept and VoidScan offers to
  retry with Subfinder. The combined results are reported as
  `amass+subfinder`.
- Large terminal result tables are truncated to the first 50 rows. The full
  results are always included in saved reports.
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
│   ├── errors.py
│   ├── execution.py
│   ├── process.py
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
├── config.example.toml
├── README.md
├── CHANGELOG.md
└── ROADMAP.md
