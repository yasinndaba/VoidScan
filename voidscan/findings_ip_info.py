"""IP information findings analyzer for VoidScan."""

from voidscan.findings import Finding, Severity
from voidscan.scanners.ip_info import IPInfoResult


def analyze_ip_info_result(result: IPInfoResult) -> list[Finding]:
    """Convert IP information into structured security findings."""

    findings: list[Finding] = []

    if result.is_private:
        findings.append(
            Finding(
                title="Private IP Address Identified",
                severity=Severity.INFO,
                description=(
                    f"The target resolved to private IP address "
                    f"{result.address}."
                ),
                evidence=result.address,
                recommendation=(
                    "Verify that the address belongs to the authorized "
                    "internal network and review its exposed services."
                ),
            )
        )

    if result.is_loopback:
        findings.append(
            Finding(
                title="Loopback IP Address Identified",
                severity=Severity.INFO,
                description=(
                    f"The target resolved to loopback address "
                    f"{result.address}."
                ),
                evidence=result.address,
                recommendation=(
                    "Verify that loopback addressing is expected for the "
                    "target."
                ),
            )
        )

    if result.is_reserved:
        findings.append(
            Finding(
                title="Reserved IP Address Identified",
                severity=Severity.INFO,
                description=(
                    f"The target resolved to reserved IP address "
                    f"{result.address}."
                ),
                evidence=result.address,
                recommendation=(
                    "Verify that the reserved address is expected and "
                    "appropriately handled by the environment."
                ),
            )
        )

    if result.is_multicast:
        findings.append(
            Finding(
                title="Multicast IP Address Identified",
                severity=Severity.INFO,
                description=(
                    f"The target resolved to multicast address "
                    f"{result.address}."
                ),
                evidence=result.address,
                recommendation=(
                    "Verify that multicast addressing is required and "
                    "appropriately restricted."
                ),
            )
        )

    if result.reverse_dns:
        findings.append(
            Finding(
                title="Reverse DNS Record Identified",
                severity=Severity.INFO,
                description=(
                    f"The IP address {result.address} resolves to "
                    f"{result.reverse_dns}."
                ),
                evidence=result.reverse_dns,
                recommendation=(
                    "Verify that the reverse DNS record is expected and "
                    "does not disclose unnecessary information."
                ),
            )
        )

    return findings
