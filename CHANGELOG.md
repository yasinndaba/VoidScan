# Changelog

All notable changes to VoidScan will be documented here.

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

* Terminal reporting
* HTML reporting
* Scan summaries
* Unified findings model
* Integration testing expansion
* Static analysis
* Code quality improvements
* GitHub Actions CI/CD
* Packaging validation
* Architecture documentation
* Demonstration lab
* Version 1.0.0 release
