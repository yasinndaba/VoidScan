# VoidScan Development Milestones

Task-level planning lives in [ROADMAP.md](../ROADMAP.md).

## Milestone 0 — Project Foundation

Status: Complete

Objectives:

* Establish the Python project structure.
* Create an isolated virtual environment.
* Create the initial VoidScan package.
* Implement the first CLI entry point.
* Configure Python packaging.
* Add automated testing.
* Establish Git version control.
* Create initial project documentation.

Completed:

* [x] Git repository initialized
* [x] Python virtual environment created
* [x] Project package created
* [x] CLI entry point implemented
* [x] pyproject.toml created
* [x] pytest configured
* [x] Initial test implemented
* [x] README created
* [x] Project structure documented

## Milestone 1 — Core Framework

Status: Complete

Completed:

* [x] Target validation
* [x] Target management
* [x] Configuration system
* [x] Structured logging and log viewer
* [x] Startup dependency checks
* [x] Settings and tool status panel
* [x] Error handling
* [x] Scan profiles
* [x] Application configuration

## Milestone 2 — Nmap Engine

Status: Complete

Completed:

* [x] Nmap integration
* [x] Safe subprocess execution
* [x] Scan profiles
* [x] Structured scan results
* [x] Error handling
* [x] Timeout handling
* [x] Port and service extraction
* [x] Non-root TCP connect scan fallback

## Milestone 3 — Network Discovery

Status: Complete

Completed:

* [x] Host discovery
* [x] Network range validation
* [x] Discovery results
* [x] Structured output
* [x] CIDR validation
* [x] Timeout/error handling

## Milestone 4 — Web Reconnaissance

Status: Complete

Completed:

* [x] Subdomain enumeration
* [x] Directory enumeration
* [x] URL validation
* [x] Tool integration
* [x] Structured findings
* [x] FFUF integration
* [x] DIRB integration
* [x] Subfinder integration
* [x] Amass integration
* [x] Wordlist validation
* [x] URL and hostname target support
* [x] Clean DIRB result parsing

## Milestone 5 — Reporting

Status: Complete

Completed:

* [x] Terminal reports
* [x] JSON reports
* [x] HTML reports
* [x] Scan summaries
* [x] Findings
* [x] Unified reporting structure
* [x] Report storage and management
* [x] Unique timestamped JSON and HTML filenames

## Milestone 6 — Testing & Quality

Status: In Progress

Completed:

* [x] Unit tests
* [x] Scanner tests
* [x] Target management tests
* [x] Validation tests
* [x] Mocked subprocess/tool tests
* [x] Error handling tests
* [x] System Monitor tests
* [x] Shell/tool dependency checks
* [x] Graceful Ctrl+C, cancellation, and EOF handling
* [x] Manual full-workflow validation
* [x] Worker-thread scans with live progress and elapsed time
* [x] Ctrl+C offers cancel or exit and terminates child processes
* [x] TOML configuration with environment and CLI overrides
* [x] Configurable timeouts and host-discovery limits
* [x] Amass partial results with optional Subfinder retry
* [x] Findings deduplication with merged evidence
* [x] Versioned report schema
* [x] Consistent empty, timeout, missing-tool, and invalid-input states
* [x] Ruff linting and formatting
* [x] Mypy type checking for `voidscan/`
* [x] Coverage gate at 85% overall and 90% for scanners and reporters
* [x] 288 automated tests passing

Remaining:

* [ ] Automated integration tests
* [ ] Code quality improvements

## Milestone 7 — CI/CD

Status: Planned

Planned:

* [ ] GitHub Actions
* [ ] Automated testing
* [ ] Linting
* [ ] Packaging checks

## Milestone 8 — Version 1.0

Status: Planned

Planned:

* [ ] Stable CLI
* [ ] Complete documentation
* [ ] Architecture documentation
* [ ] Screenshots
* [ ] Demonstration lab
* [ ] Release notes
* [ ] Version 1.0.0
