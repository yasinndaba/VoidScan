# Changelog

All notable changes to VoidScan will be documented here.

## [Unreleased]

### Added

* Structured security findings in JSON and HTML reports
* Severity levels (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
* Findings analyzers for Nmap, host discovery, subdomains, directory enumeration, and IP information
* Findings tables in terminal output after each scan
* Findings section in HTML reports, with severity badges and escaped evidence
* Terminal report summary shown after saving a report
* Report summaries report finding counts and a severity breakdown
* HTML reporter tests, subdomain scanner tests, and discovery scanner tests
* URL targets and bare-host directory enumeration
* Startup dependency warnings and external tool status in Settings
* In-app log viewer
* Non-root TCP connect fallback for Nmap scan profiles
* Open-port findings for all services, with risk-based severities
* Concurrent host discovery with a progress bar and a 4096-host cap
* Unique timestamped HTML report filenames
* Graceful Ctrl+D/EOF handling
* Tests for URL targets, non-root scans, DIRB/Amass parsing, discovery limits, and report filenames
* Prioritized roadmap for the remaining reliability, quality, and v1.0 work

### Changed

* A report is now built once per scan and reused for both JSON and HTML output
* Report summaries now count findings even when there are none
* DIRB and FFUF results are reported as full URLs instead of raw tool lines
* Amass and Subfinder output is filtered to valid hostnames
* Terminal result tables are capped at 50 rows; full results remain in reports
* Logging now writes to `~/.voidscan/logs/voidscan.log` and records scan commands
* `rich` is declared as a runtime dependency, with a `test` extra for pytest
* README now documents installation, usage, target types, and limits
* Test suite consolidated under `tests/`; **174 tests passing**

### Fixed

* Directory Enumeration is reachable: URL targets are accepted, and bare hosts
  fall back to `http://`
* Nmap findings no longer miss open ports whose service is not SSH/HTTP/HTTPS
* Standard and Full Nmap profiles work without root privileges
* DIRB banner/footer lines are no longer counted as discovered content
* Amass banner and session lines are no longer counted as subdomains
* View Logs and Settings are implemented instead of placeholders
* HTML reports no longer overwrite previous reports of the same scan type
* Ctrl+D at a prompt no longer crashes with an `EOFError` traceback

### Removed

* Duplicate `voidscan/tests/` tree, superseded by `tests/`
* Unused placeholder module helper

## [0.1.0] - 2026-09-06

### Added

* Initial Python project structure
* VoidScan package
* CLI entry point
* Python packaging configuration
* pytest configuration
* Automated test suite
* README documentation
* Development milestone documentation
* Git repository
* Target validation
* Target management
* Application configuration
* Structured logging
* Error handling
* Nmap scanning engine
* Nmap quick, standard, and full scan profiles
* Safe Nmap subprocess execution
* Nmap timeout handling
* Live host discovery
* CIDR network validation
* Subdomain enumeration
* Subfinder integration
* Amass integration
* Directory enumeration
* FFUF integration
* DIRB integration
* URL validation
* IP information scanner
* IPv4 and IPv6 detection
* Private, loopback, reserved, and multicast address detection
* Reverse DNS lookup
* System monitoring
* Hostname, operating system, kernel, architecture, CPU, memory, disk, and uptime information
* Standardized report generation
* JSON report generation
* Automatic report timestamps
* Scanner result serialization
* Nmap JSON report generation
* Report storage under `~/.voidscan/reports/`
* Interactive terminal menu
* Target selection for reconnaissance modules

### Testing

* Added unit tests for core framework components
* Added Nmap scanner tests
* Added network discovery tests
* Added subdomain enumeration tests
* Added directory enumeration tests
* Added IP information tests
* Added system monitor tests
* Added target management tests
* Added validator tests
* Added configuration tests
* Added CLI tests
* Added JSON reporter tests
* Added network scan and reporting integration tests
* Current automated test suite: **54 tests passing**

### Security

* Added validated target handling
* Added safe subprocess execution for external security tools
* Avoided shell command execution through `shell=True`
* Added external tool availability checks
* Added scanner timeout handling
* Added structured error handling

### Documentation

* Expanded README with current project capabilities
* Documented project architecture
* Documented installation and development workflow
* Documented external tool dependencies
* Documented reporting functionality
* Documented security and authorized-use requirements
* Added development roadmap and milestone tracking

### In Progress

* Integration testing expansion
* Static analysis
* Code quality improvements
* GitHub Actions CI/CD
* Packaging validation
* Architecture documentation
* Demonstration lab
* Version 1.0.0 release
