# VoidScan

VoidScan is a modular Python-based reconnaissance and security assessment toolkit designed for authorized security testing, cybersecurity laboratories, and defensive security research.

The project is being developed as a portfolio project to demonstrate practical Python development, cybersecurity automation, reconnaissance, security tooling integration, testing, documentation, and secure software practices.

## Current Status

Version: 0.1.0

Milestone 0 — Project Foundation

Current capabilities:

* Python package structure
* Command-line entry point
* Virtual environment
* Basic automated testing
* Git-based project management

Reconnaissance capabilities such as Nmap scanning, host discovery, subdomain enumeration, and web directory enumeration will be implemented in later milestones.

## Architecture

The planned architecture is:

Target → Validation → Scan Profile → Scanner → Structured Result → Report

## Security Notice

VoidScan is intended only for systems, networks, applications, and infrastructure that you own or have explicit permission to assess.

Do not use this project to scan or enumerate unauthorized systems.

## Development

Create and activate the virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install the project:

```bash
pip install -e .
```

Run VoidScan:

```bash
voidscan
```

Run tests:

```bash
pytest
```

## Author

Yasin Ndaba
