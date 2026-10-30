"""Live host discovery findings analyzer for VoidScan."""

from voidscan.findings import Finding
from voidscan.scanners.discovery import HostDiscoveryResult
from voidscan.severity import DISCOVERY_SEVERITY


def analyze_discovery_result(
    result: HostDiscoveryResult,
) -> list[Finding]:
    """Convert a host discovery result into structured findings."""

    if not result.hosts:
        return []

    return [
        Finding(
            title="Reachable Hosts Discovered",
            severity=DISCOVERY_SEVERITY,
            description=(
                f"{result.reachable} reachable host(s) were discovered "
                f"on the {result.network} network."
            ),
            evidence="\n".join(result.hosts),
            recommendation=(
                "Review discovered hosts and verify that each system "
                "is authorized, required, and appropriately secured."
            ),
        )
    ]
