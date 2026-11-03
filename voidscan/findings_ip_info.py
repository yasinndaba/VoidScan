"""IP information findings analyzer for VoidScan."""

from voidscan.findings import Confidence, Finding
from voidscan.scanners.ip_info import IPInfoResult
from voidscan.severity import IP_INFO_SEVERITY


def analyze_ip_info_result(result: IPInfoResult) -> list[Finding]:
    """Convert IP information into structured security findings."""

    findings: list[Finding] = []

    if result.is_private:
        findings.append(
            Finding(
                title="Private IP Address Identified",
                severity=IP_INFO_SEVERITY,
                description=(
                    f"The target resolved to private IP address "
                    f"{result.address}."
                ),
                evidence=result.address,
                recommendation=(
                    "Verify that the address belongs to the authorized "
                    "internal network and review its exposed services."
                ),
                confidence=Confidence.HIGH,
                why_it_matters=(
                    "Private addressing marks an internal asset, which can "
                    "expose services that are not reachable from outside."
                ),
            )
        )

    if result.is_loopback:
        findings.append(
            Finding(
                title="Loopback IP Address Identified",
                severity=IP_INFO_SEVERITY,
                description=(
                    f"The target resolved to loopback address "
                    f"{result.address}."
                ),
                evidence=result.address,
                recommendation=(
                    "Verify that loopback addressing is expected for the "
                    "target."
                ),
                confidence=Confidence.HIGH,
                why_it_matters=(
                    "Loopback targets usually indicate local testing and "
                    "should not be mistaken for remote exposure."
                ),
            )
        )

    if result.is_reserved:
        findings.append(
            Finding(
                title="Reserved IP Address Identified",
                severity=IP_INFO_SEVERITY,
                description=(
                    f"The target resolved to reserved IP address "
                    f"{result.address}."
                ),
                evidence=result.address,
                recommendation=(
                    "Verify that the reserved address is expected and "
                    "appropriately handled by the environment."
                ),
                confidence=Confidence.HIGH,
                why_it_matters=(
                    "Reserved ranges are not routable on the public "
                    "internet, so findings here usually indicate lab or "
                    "misconfigured addressing."
                ),
            )
        )

    if result.is_multicast:
        findings.append(
            Finding(
                title="Multicast IP Address Identified",
                severity=IP_INFO_SEVERITY,
                description=(
                    f"The target resolved to multicast address "
                    f"{result.address}."
                ),
                evidence=result.address,
                recommendation=(
                    "Verify that multicast addressing is required and "
                    "appropriately restricted."
                ),
                confidence=Confidence.HIGH,
                why_it_matters=(
                    "Multicast addresses identify groups rather than single "
                    "hosts, so probes can affect multiple systems."
                ),
            )
        )

    if result.reverse_dns:
        findings.append(
            Finding(
                title="Reverse DNS Record Identified",
                severity=IP_INFO_SEVERITY,
                description=(
                    f"The IP address {result.address} resolves to "
                    f"{result.reverse_dns}."
                ),
                evidence=result.reverse_dns,
                recommendation=(
                    "Verify that the reverse DNS record is expected and "
                    "does not disclose unnecessary information."
                ),
                confidence=Confidence.MEDIUM,
                why_it_matters=(
                    "Reverse DNS names can expose internal naming "
                    "conventions and help map services, but they are not "
                    "proof of ownership."
                ),
            )
        )

    return findings
