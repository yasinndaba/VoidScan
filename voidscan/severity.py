"""Central severity policy for VoidScan findings.

Every analyzer takes its severities from this module so the risk model is
defined, reviewed, and tested in one place. Changing a severity here changes
it everywhere, including reports and the terminal summary.
"""

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    """Severity levels for security findings."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Most severe first, for sorting and for the summary breakdown.
SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

SEVERITY_RANK = {
    severity.value: index for index, severity in enumerate(SEVERITY_ORDER)
}

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


@dataclass(frozen=True)
class ServiceRule:
    """Describe how an exposed service should be reported."""

    title: str
    severity: Severity
    description: str
    recommendation: str


SSH_RULE = ServiceRule(
    "SSH Service Detected",
    Severity.INFO,
    "An SSH service was detected on the target.",
    "Review whether SSH exposure is required and restrict access "
    "with firewall rules or key-based authentication.",
)

HTTP_RULE = ServiceRule(
    "HTTP Service Detected",
    Severity.INFO,
    "An HTTP web service was detected on the target.",
    "Review the web service configuration and ensure sensitive "
    "traffic uses HTTPS.",
)

HTTPS_RULE = ServiceRule(
    "HTTPS Service Detected",
    Severity.INFO,
    "An HTTPS web service was detected on the target.",
    "Verify that TLS is correctly configured and kept up to date.",
)

FTP_RULE = ServiceRule(
    "FTP Service Detected",
    Severity.MEDIUM,
    "A plaintext FTP service was detected on the target.",
    "Prefer SFTP or FTPS, disable anonymous access, and restrict "
    "the service to trusted networks.",
)

TELNET_RULE = ServiceRule(
    "Telnet Service Detected",
    Severity.HIGH,
    "A plaintext Telnet service was detected on the target.",
    "Disable Telnet and use SSH instead. Telnet sends credentials "
    "and session data unencrypted.",
)

SMB_RULE = ServiceRule(
    "SMB Service Detected",
    Severity.MEDIUM,
    "An SMB file-sharing service was detected on the target.",
    "Restrict SMB access to trusted networks and verify that the "
    "service is fully patched.",
)

RDP_RULE = ServiceRule(
    "Remote Desktop Service Detected",
    Severity.MEDIUM,
    "A Remote Desktop service was detected on the target.",
    "Restrict Remote Desktop access with a firewall, require strong "
    "authentication, and keep the service patched.",
)

VNC_RULE = ServiceRule(
    "VNC Service Detected",
    Severity.MEDIUM,
    "A VNC remote desktop service was detected on the target.",
    "Require authentication for VNC, tunnel it over SSH, and restrict "
    "access to trusted hosts.",
)

REDIS_RULE = ServiceRule(
    "Redis Service Detected",
    Severity.HIGH,
    "A Redis service was detected on the target.",
    "Bind Redis to a trusted interface, enable authentication, and "
    "never expose it directly to the internet.",
)

DATABASE_RULE = ServiceRule(
    "Database Service Detected",
    Severity.MEDIUM,
    "A database service was detected on the target.",
    "Restrict database access to application hosts and require "
    "strong authentication.",
)


# Ordered from most specific to least specific. The first matching
# prefix wins, so HTTPS is checked before HTTP.
SERVICE_RULES: tuple[tuple[str, ServiceRule], ...] = (
    ("https", HTTPS_RULE),
    ("ssl/https", HTTPS_RULE),
    ("ssl/http", HTTP_RULE),
    ("http", HTTP_RULE),
    ("ssh", SSH_RULE),
    ("ftp", FTP_RULE),
    ("telnet", TELNET_RULE),
    ("microsoft-ds", SMB_RULE),
    ("netbios-ssn", SMB_RULE),
    ("smb", SMB_RULE),
    ("ms-wbt-server", RDP_RULE),
    ("rdp", RDP_RULE),
    ("vnc", VNC_RULE),
    ("mysql", DATABASE_RULE),
    ("postgresql", DATABASE_RULE),
    ("ms-sql-s", DATABASE_RULE),
    ("mongodb", DATABASE_RULE),
    ("redis", REDIS_RULE),
)

PORT_RULES: dict[int, ServiceRule] = {
    21: FTP_RULE,
    23: TELNET_RULE,
    139: SMB_RULE,
    445: SMB_RULE,
    1433: DATABASE_RULE,
    3306: DATABASE_RULE,
    3389: RDP_RULE,
    5432: DATABASE_RULE,
    5900: VNC_RULE,
    6379: REDIS_RULE,
    27017: DATABASE_RULE,
}

GENERIC_RULE = ServiceRule(
    "Open Port Detected",
    Severity.INFO,
    "An open port was detected on the target.",
    "Review whether this port needs to be reachable and restrict "
    "access where appropriate.",
)


# Presence-only analyzers report an asset, not a vulnerability, so their
# baseline is informational until a dedicated check raises it.
DISCOVERY_SEVERITY = Severity.INFO
SUBDOMAIN_SEVERITY = Severity.INFO
DIRECTORY_SEVERITY = Severity.INFO
IP_INFO_SEVERITY = Severity.INFO

ANALYZER_SEVERITIES: dict[str, Severity] = {
    "discovery": DISCOVERY_SEVERITY,
    "subdomains": SUBDOMAIN_SEVERITY,
    "directories": DIRECTORY_SEVERITY,
    "ip_info": IP_INFO_SEVERITY,
}


def rule_for_service(port: int, service: str) -> ServiceRule:
    """Return the best matching severity rule for a service and port."""

    for prefix, rule in SERVICE_RULES:
        if service.startswith(prefix):
            return rule

    return PORT_RULES.get(port, GENERIC_RULE)
