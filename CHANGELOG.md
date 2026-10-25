# Changelog

All notable changes to VoidScan will be documented here.

## [Unreleased]

### Added

* Ruff linting and formatting with a `dev` extras group
* Mypy type checking for `voidscan/` with strict untyped-definition checks
* README section documenting the local development checks
* Coverage gate: 85% overall and 90% for scanners and reporters
* Menu-flow tests covering target management, every scan flow, reports, logs, settings, and the main loop

### Changed

* Test suite expanded to **288 tests**
* `pytest-cov` is part of the development extras, and `scripts/check_coverage.py` enforces per-package thresholds
* The package now targets Python 3.10 consistently for formatting, linting, and type checking
* TOML loading and environment overrides are fully typed and mypy-clean
* Subprocess startup has explicit POSIX and non-POSIX branches, and timeouts chain their original exception
* The code base is formatted with Ruff at a 79-character line length

## [0.2.0] - 2026-10-25

### Added

* Scans run on a worker thread, so the menu stays responsive
* Live progress with elapsed time for Nmap, FFUF, DIRB, Subfinder, Amass, and host discovery
* Ctrl+C during a scan offers **cancel** or **exit** instead of dropping straight out of the menu
* Cancellation terminates the active process group within two seconds and leaves no orphaned tools
* Reusable subprocess runner with timeout, heartbeat, and process-group cleanup
* TOML configuration at `~/.voidscan/config.toml`, with per-setting validation and safe fallbacks
* `VOIDSCAN_*` environment overrides and `--config`, `--data-dir`, `--log-dir`, and `--report-dir` flags
* Configurable per-tool timeouts; defaults preserve the previous values
* Configurable host-discovery limit, worker count, and ping timeout
* Startup configuration warnings that do not stop VoidScan
* Partial Amass results on timeout, plus an optional Subfinder retry whose results merge into `amass+subfinder`
* Findings deduplication that collapses repeated findings and keeps every unique evidence line
* `schema_version` in every JSON and HTML report, with a test that locks the report shape
* Consistent panels for empty results, timeouts, missing tools, and invalid input
* `config.example.toml` as a documented starting point
* Findings tables in terminal output after each scan
* Findings section in HTML reports, with severity badges and escaped evidence
* Terminal report summary shown after saving a report
* URL targets and bare-host directory enumeration
* Startup dependency warnings and external tool status in Settings
* In-app log viewer
* Non-root TCP connect fallback for Nmap scan profiles
* Open-port findings for all services, with risk-based severities
* Unique timestamped JSON and HTML report filenames
* Graceful Ctrl+D/EOF handling
* Prioritized roadmap for the remaining reliability, quality, and v1.0 work

### Changed

* Every external tool call now goes through the cancellable process runner
* Amass `-timeout` is derived from the configured timeout in seconds
* Configuration precedence is defaults, then `config.toml`, then environment variables, then CLI flags
* Report `version` now comes from the package version instead of a literal
* A report is built once per scan and reused for both JSON and HTML output
* Report summaries count findings even when there are none
* DIRB and FFUF results are reported as full URLs instead of raw tool lines
* Amass and Subfinder output is filtered to valid hostnames
* Terminal result tables are capped at 50 rows; full results remain in reports
* Logging writes to `~/.voidscan/logs/voidscan.log` and records scan commands
* `rich` is a runtime dependency, with a `test` extra for pytest and a `tomli` fallback on Python 3.10
* README documents configuration, cancellation, timeouts, discovery limits, and the report schema
* Test suite expanded and consolidated under `tests/`; **215 tests passing**

### Fixed

* Long scans no longer block the menu or appear hung
* Ctrl+C no longer exits VoidScan or leaves child processes running
* Amass timeouts no longer discard partial subdomain output
* Repeated findings no longer appear multiple times in terminal, JSON, or HTML output
* Directory Enumeration is reachable: URL targets are accepted, and bare hosts fall back to `http://`
* Nmap findings no longer miss open ports whose service is not SSH/HTTP/HTTPS
* Standard and Full Nmap profiles work without root privileges
* DIRB banner/footer lines are no longer counted as discovered content
* Amass banner and session lines are no longer counted as subdomains
* View Logs and Settings are implemented instead of placeholders
* HTML reports no longer overwrite previous reports of the same scan type
* Ctrl+D at a prompt no longer crashes with an `EOFError` traceback

### Removed

* Hard-coded timeouts and discovery limits from individual scanners
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
