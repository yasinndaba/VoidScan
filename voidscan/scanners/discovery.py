"""Live host discovery engine for VoidScan."""

import ipaddress
import subprocess
from dataclasses import dataclass


@dataclass
class HostDiscoveryResult:
    """Represent a host discovery result."""

    network: str
    hosts: list[str]
    scanned: int
    reachable: int

def validate_network(network: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Validate and return a network in explicit CIDR notation."""

    network = network.strip()

    if "/" not in network:
        raise ValueError(
            "Invalid network. Use CIDR notation such as 192.168.1.0/24."
        )

    try:
        return ipaddress.ip_network(network, strict=False)
    except ValueError as exc:
        raise ValueError(
            "Invalid network. Use CIDR notation such as 192.168.1.0/24."
        ) from exc

def host_is_up(host: str, timeout: int = 1) -> bool:
    """Check whether a host responds to an ICMP ping."""

    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout + 1,
        )

        return result.returncode == 0

    except (OSError, subprocess.TimeoutExpired):
        return False


def discover_hosts(network: str) -> HostDiscoveryResult:
    """Discover reachable hosts in a network."""

    validated_network = validate_network(network)

    hosts = [str(host) for host in validated_network.hosts()]

    reachable = []

    for host in hosts:
        if host_is_up(host):
            reachable.append(host)

    return HostDiscoveryResult(
        network=str(validated_network),
        hosts=reachable,
        scanned=len(hosts),
        reachable=len(reachable),
    )