"""Nmap security findings analyzer for VoidScan."""

import re
from dataclasses import dataclass

from voidscan.findings import Finding, Severity
from voidscan.scanners.nmap import NmapResult


@dataclass(frozen=True)
class ServiceRule:
    """Describe how an exposed service should be reported."""

    title: str
    severity: Severity
    description: str
    recommendation: str


_SSH_RULE = ServiceRule(
    "SSH Service Detected",
    Severity.INFO,
    "An SSH service was detected on the target.",
    "Review whether SSH exposure is required and restrict access "
    "with firewall rules or key-based authentication.",
)

_HTTP_RULE = ServiceRule(
    "HTTP Service Detected",
    Severity.INFO,
    "An HTTP web service was detected on the target.",
    "Review the web service configuration and ensure sensitive "
    "traffic uses HTTPS.",
)

_HTTPS_RULE = ServiceRule(
    "HTTPS Service Detected",
    Severity.INFO,
    "An HTTPS web service was detected on the target.",
    "Verify that TLS is correctly configured and kept up to date.",
)

_FTP_RULE = ServiceRule(
    "FTP Service Detected",
    Severity.MEDIUM,
    "A plaintext FTP service was detected on the target.",
    "Prefer SFTP or FTPS, disable anonymous access, and restrict "
    "the service to trusted networks.",
)

_TELNET_RULE = ServiceRule(
    "Telnet Service Detected",
    Severity.HIGH,
    "A plaintext Telnet service was detected on the target.",
    "Disable Telnet and use SSH instead. Telnet sends credentials "
    "and session data unencrypted.",
)

_SMB_RULE = ServiceRule(
    "SMB Service Detected",
    Severity.MEDIUM,
    "An SMB file-sharing service was detected on the target.",
    "Restrict SMB access to trusted networks and verify that the "
    "service is fully patched.",
)

_RDP_RULE = ServiceRule(
    "Remote Desktop Service Detected",
    Severity.MEDIUM,
    "A Remote Desktop service was detected on the target.",
    "Restrict Remote Desktop access with a firewall, require strong "
    "authentication, and keep the service patched.",
)

_VNC_RULE = ServiceRule(
    "VNC Service Detected",
    Severity.MEDIUM,
    "A VNC remote desktop service was detected on the target.",
    "Require authentication for VNC, tunnel it over SSH, and restrict "
    "access to trusted hosts.",
)

_REDIS_RULE = ServiceRule(
    "Redis Service Detected",
    Severity.HIGH,
    "A Redis service was detected on the target.",
    "Bind Redis to a trusted interface, enable authentication, and "
    "never expose it directly to the internet.",
)

_DATABASE_RULE = ServiceRule(
    "Database Service Detected",
    Severity.MEDIUM,
    "A database service was detected on the target.",
    "Restrict database access to application hosts and require "
    "strong authentication.",
)


# Ordered from most specific to least specific. The first matching
# prefix wins, so HTTPS is checked before HTTP.
SERVICE_RULES: tuple[tuple[str, ServiceRule], ...] = (
    ("https", _HTTPS_RULE),
    ("ssl/https", _HTTPS_RULE),
    ("ssl/http", _HTTP_RULE),
    ("http", _HTTP_RULE),
    ("ssh", _SSH_RULE),
    ("ftp", _FTP_RULE),
    ("telnet", _TELNET_RULE),
    ("microsoft-ds", _SMB_RULE),
    ("netbios-ssn", _SMB_RULE),
    ("smb", _SMB_RULE),
    ("ms-wbt-server", _RDP_RULE),
    ("rdp", _RDP_RULE),
    ("vnc", _VNC_RULE),
    ("mysql", _DATABASE_RULE),
    ("postgresql", _DATABASE_RULE),
    ("ms-sql-s", _DATABASE_RULE),
    ("mongodb", _DATABASE_RULE),
    ("redis", _REDIS_RULE),
)

PORT_RULES: dict[int, ServiceRule] = {
    21: _FTP_RULE,
    23: _TELNET_RULE,
    139: _SMB_RULE,
    445: _SMB_RULE,
    1433: _DATABASE_RULE,
    3306: _DATABASE_RULE,
    3389: _RDP_RULE,
    5432: _DATABASE_RULE,
    5900: _VNC_RULE,
    6379: _REDIS_RULE,
    27017: _DATABASE_RULE,
}

GENERIC_RULE = ServiceRule(
    "Open Port Detected",
    Severity.INFO,
    "An open port was detected on the target.",
    "Review whether this port needs to be reachable and restrict "
    "access where appropriate.",
)

OPEN_PORT_PATTERN = re.compile(
    r"^\s*(\d+)/(tcp|udp)\s+(open(?:\|filtered)?)\s+(\S+)",
    re.IGNORECASE,
)


def _rule_for(port: int, service: str) -> ServiceRule:
    """Return the best matching rule for a service and port."""

    for prefix, rule in SERVICE_RULES:
        if service.startswith(prefix):
            return rule

    return PORT_RULES.get(port, GENERIC_RULE)


def analyze_nmap_result(result: NmapResult) -> list[Finding]:
    """Convert an Nmap result into structured security findings."""

    if not result.success:
        return []

    findings: list[Finding] = []

    for line in result.output.splitlines():
        match = OPEN_PORT_PATTERN.search(line)

        if not match:
            continue

        port = int(match.group(1))
        protocol = match.group(2).lower()
        state = match.group(3).lower()
        service = match.group(4).lower()

        rule = _rule_for(port, service)

        evidence = line.strip()

        findings.append(
            Finding(
                title=rule.title,
                severity=rule.severity,
                description=(
                    f"{rule.description} "
                    f"Detected {protocol.upper()} port {port} "
                    f"({service}, {state})."
                ),
                evidence=evidence,
                recommendation=rule.recommendation,
            )
        )

    return findings
