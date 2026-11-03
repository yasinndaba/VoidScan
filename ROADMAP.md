# VoidScan Roadmap

Current baseline: **v0.3.0**, **412 tests passing** plus 4 optional live
tests, **94.3% coverage**, Linux supported. Ruff, formatting, and mypy pass
on the current tree.

Milestones 0–7 are complete. The v0.2 reliability milestone and the v0.3
quality gate are complete; the next focus is v0.4 insight and polish.
This roadmap replaces the original phase list with an actionable plan for the
remaining work, ordered by user impact rather than feature count.

## Where we are

Working today:

- Nmap scans with quick, standard, and full profiles, including non-root scans
- Scans run on a worker thread with live progress, elapsed time, and Ctrl+C cancellation
- TOML configuration with environment and CLI overrides, configurable timeouts, and configurable discovery limits
- Concurrent host discovery with progress and a configurable host cap
- Subfinder and Amass enumeration with clean output parsing, partial Amass results, and Subfinder retry
- FFUF and DIRB enumeration with full-URL results
- IP information and system monitoring
- Findings with severity, confidence, and plain-language context in the terminal, JSON, and HTML, deduplicated with merged evidence
- Versioned reports with unique timestamped JSON and HTML filenames
- Report browser that lists saved reports by date, type, target, finding count, and format, and opens JSON or HTML
- File logging, startup dependency checks, log viewer, and settings panel
- Structured Nmap, FFUF, and Subfinder output with tested text fallbacks
- First-scan authorization confirmation with a `--yes` override for scripted runs
- Linting, formatting, type checking, coverage gates, and a CI matrix on Python 3.10–3.13

Known gaps this roadmap addresses:

- Settings cannot be edited
- No paging or filtering for large terminal result tables
- Findings are still mostly presence-based; service-version awareness is pending
- No scope file yet
- No architecture docs, screenshots, or demo lab

## Priority legend

| Priority | Meaning |
|---|---|
| **P0** | Blocks reliable day-to-day use; do first |
| **P1** | Required for a credible v1.0 |
| **P2** | High-value polish; can slip past v1.0 |
| **Post-1.0** | Explicitly deferred |

Sizes are relative: **S** ≈ half a day, **M** ≈ 1–3 days, **L** ≈ 1 week+.
Durations in the milestone plan are indicative for a solo developer.

## Workstream A — Scan control and responsiveness

Goal: every long-running operation is observable, cancellable, and never
traps the user in a blocking subprocess.

| ID | Task | Priority | Size | Done when |
|---|---|---|---|---|
| A1 | Run scanner calls on a worker thread | P0 | M | The menu stays responsive during scans; results return to the UI thread safely |
| A2 | Cancel the active scan | P0 | M | Ctrl+C offers “cancel scan” or “exit”; the child process is terminated within 2 s; no orphans remain |
| A3 | Live progress for slow tools | P0 | M | Nmap, FFUF, DIRB, Subfinder, and Amass show elapsed time and a heartbeat instead of a static spinner |
| A4 | Structured tool output | P1 | L | Nmap uses `-oX -`, FFUF `-json`, Subfinder `-json`; text parsers remain as tested fallbacks |
| A5 | Amass timeout handling | P0 | S | On timeout the user can retry with Subfinder; partial results can be returned and reported |
| A6 | Configurable timeouts | P0 | S | Per-tool timeouts live in config with today’s values as defaults |

## Workstream B — Configuration, scale, and scope

Goal: limits are explicit, configurable, and enforced before expensive work
starts; scans stay inside the user’s authorized scope.

| ID | Task | Priority | Size | Done when |
|---|---|---|---|---|
| B1 | User config file | P0 | M | `~/.voidscan/config.toml` is loaded at startup; CLI/env overrides work; invalid config warns and falls back safely |
| B2 | Configurable discovery limits | P0 | S | Host cap (default 4096) and worker count are configurable in config/Settings |
| B3 | Explicit IPv6 policy | P1 | S | Oversized networks are rejected before address enumeration; docs explain supported IPv6 range sizes |
| B4 | Authorization confirmation | P1 | S | First scan per session requires explicit confirmation; `--yes` supports scripted use |
| B5 | Scope file / allowlist | P2 | M | An optional scope file rejects out-of-scope targets with a clear message |
| B6 | Audit record per scan | P2 | S | Logs and report metadata record start/end time, command, duration, and result count |

## Workstream C — Findings and risk quality

Goal: findings explain *why* something matters and avoid noise, without
pretending to be a full vulnerability scanner.

| ID | Task | Priority | Size | Done when |
|---|---|---|---|---|
| C1 | Version-aware service matching | P2 | M | Nmap product/version is used in evidence; known-outdated service versions are flagged with a caveat |
| C2 | Central severity policy | P1 | S | All analyzer severity mappings live in one module with table-driven tests |
| C3 | Deduplicate findings | P0 | S | Repeated host/port/service results collapse into one finding that keeps all evidence |
| C4 | TLS and HTTP header checks | P2 | L | HTTPS targets report certificate expiry and missing security headers as LOW/MEDIUM findings |
| C5 | Confidence and context | P2 | M | Findings carry a confidence level and a short “why this matters” note; reporters render both |

## Workstream D — Reporting and UX

Goal: results are easy to find, read, and compare after a scan finishes.

| ID | Task | Priority | Size | Done when |
|---|---|---|---|---|
| D1 | Report browser | P2 | M | The menu lists reports by date, type, target, and finding count, and opens JSON/HTML |
| D2 | Report schema version | P0 | S | Every report includes `schema_version`; a test locks the current shape |
| D3 | Paging and filtering | P2 | M | Large terminal tables can page or filter by substring; saved reports remain complete |
| D4 | Consistent empty/error states | P0 | S | Every flow has clear panels for no results, missing tools, invalid input, and timeouts |
| D5 | Editable settings | P2 | M | Timeouts, limits, wordlist path, and report directory can be edited, validated, and persisted |
| D6 | HTML report polish | P2 | S | Severity summary, scan metadata, and anchor links make long reports navigable |

## Workstream E — Engineering quality

Goal: changes are verified automatically, and regressions are caught before
they reach a user.

| ID | Task | Priority | Size | Done when |
|---|---|---|---|---|
| E1 | Integration test harness | P1 | L | Local HTTP server plus fake tool binaries cover network, discovery, subdomain, directory, and report flows without internet access |
| E2 | Coverage gate | P1 | S | `pytest --cov` enforces ≥85% overall and ≥90% for scanners and reporters |
| E3 | Lint and format | P1 | S | Ruff check and format pass locally and in CI; pre-commit hook documented |
| E4 | Type checking | P1 | M | Mypy (or Pyright) passes on `voidscan/`; public scanner functions are typed |
| E5 | CI matrix | P1 | M | GitHub Actions runs lint, types, tests, and package build on Python 3.10–3.13 |
| E6 | Packaging smoke test | P1 | S | `python -m build`, install the wheel in a clean venv, and run `voidscan --version` in CI |
| E7 | Optional live-tool tests | P2 | S | Network/tool tests are marked and skipped by default; a documented command runs them locally |

## Workstream F — Documentation and release

Goal: a new user can install, understand, demonstrate, and trust the project.

| ID | Task | Priority | Size | Done when |
|---|---|---|---|---|
| F1 | Architecture document | P1 | M | `docs/architecture.md` covers modules, data flow, extension points, and the authorized-use model |
| F2 | User guide and screenshots | P1 | M | Docs cover install, every flow, config, reports, and troubleshooting; screenshots are committed |
| F3 | Demo lab | P1 | M | A Docker Compose or scripted local lab provides safe targets for a demonstration |
| F4 | Release checklist | P1 | S | Version bump, changelog, tag, artifacts, and clean-install verification are documented |
| F5 | v1.0.0 release | P1 | S | All P0/P1 work is closed, CI is green, docs are complete, and the release is tagged |

## Milestone plan

### v0.2 — Reliable scans

Status: Complete (v0.2.0, 2026-10-25).

Scope: A1–A3, A5–A6, B1–B2, C3, D2, D4.

Exit criteria:

- [x] A scan can be cancelled without exiting VoidScan
- [x] No scanner call blocks the menu
- [x] Timeouts and discovery limits are configurable
- [x] Reports carry a schema version
- [x] Every flow has a deliberate empty/error state

### v0.3 — Quality gate

Status: Complete (v0.3.0, 2026-10-30).

Scope: A4, B4, E1–E7.

Exit criteria:

- Structured parsers replace fragile text parsing where tools allow it
- CI is green on Python 3.10–3.13
- Coverage, lint, types, packaging, and integration tests are enforced
- A first scan requires explicit authorization confirmation

Progress:

- [x] E1 — Integration harness with fake tools and a local HTTP server
- [x] E2 — Coverage gate at 85% overall and 90% for scanners and reporters
- [x] E3 — Ruff check and format pass locally
- [x] E4 — Mypy passes on `voidscan/` with strict untyped-definition checks
- [x] E5 — GitHub Actions matrix for Python 3.10–3.13
- [x] E6 — Package build and clean-venv installation smoke test
- [x] E7 — Optional live-tool tests marked and skipped by default
- [x] B4 — First scan per session requires confirmation; `--yes` skips it
- [x] A4 — Nmap XML, FFUF JSON, and Subfinder JSON with text fallbacks

### v0.4 — Insight and polish

Scope: B3, B5–B6, C1–C2, C4–C5, D1, D3, D5–D6.

Exit criteria:

- Reports can be browsed, paged, and filtered in-app
- Settings are editable and persisted
- Findings carry severity policy, confidence, and better evidence
- Scope and audit controls are available

Progress:

- [x] C2 — Central severity policy in `voidscan/severity.py` with table-driven tests
- [x] B3 — Explicit IPv6 policy: family-aware size rejection, `ping -6`, `nmap -6`, and bracketed URLs
- [x] B6 — Audit record per scan: start/end time, command, duration, and result count in logs and report metadata
- [x] D6 — HTML report polish: severity summary, audit metadata, section nav, and per-finding anchors
- [x] C5 — Confidence and context: every finding carries a confidence level and a "why this matters" note rendered in the terminal and HTML reports
- [x] D1 — Report browser: saved reports are listed by date, type, target, and finding count, with JSON opened in the pager and HTML in the browser

### v1.0 — Release

Scope: F1–F5 plus any remaining P1 work.

Exit criteria:

- Every menu flow works without hand-editing files
- Documentation, screenshots, and demo lab are complete
- No known crash or data-loss bugs
- Version, changelog, and release notes agree

## Release criteria for v1.0

- All P0 and P1 tasks closed
- CI green on all supported Python versions
- Coverage gate met
- No open blocker bugs
- A clean install from a built wheel starts and runs a scan
- Docs cover install, usage, configuration, limits, and troubleshooting
- `CHANGELOG.md` and the package version match the tag

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| External tools change output | Parsers break silently | Prefer structured output; keep text fallbacks; use golden-file tests |
| Amass instability or slowness | Flow appears hung | Subfinder fallback, hard timeout, partial results, clear messaging |
| Scope creep in findings | v1.0 delayed | Freeze analyzer work after C1–C3; move C4–C5 past 1.0 if needed |
| Test isolation issues | Flaky CI | Reuse the existing `tmp_path` + isolated `HOME` pattern; no real network in default tests |
| CI runtime and cost | Slow feedback | Cache dependencies, split lint/type/test jobs, skip live-tool tests by default |

## Post-1.0

- macOS/BSD ping and tool discovery; Windows support
- Plugin API for third-party analyzers
- REST API or TUI for automation and headless use
- Scheduled scans and report diffing
- More web checks (TLS protocols, common misconfigurations)

## How to work this roadmap

1. Take tasks in priority order; do not start a later milestone before the
   previous exit criteria are met.
2. Use one branch/PR per workstream area, and reference task IDs in commit
   messages (for example, `A2: cancel active scans`).
3. Every task lands with tests and documentation updates.
4. Update this file and `CHANGELOG.md` when a milestone closes.
