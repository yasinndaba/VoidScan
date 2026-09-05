"""IP information engine for VoidScan."""

import ipaddress
import socket
from dataclasses import dataclass


@dataclass
class IPInfoResult:
    """Represent information about an IP address."""

    address: str
    version: str
    is_private: bool
    is_loopback: bool
    is_reserved: bool
    is_multicast: bool
    reverse_dns: str | None


def resolve_target(target: str) -> str:
    """Resolve an IP address or hostname to an IP address."""

    target = target.strip()

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target: {target}") from exc


def get_reverse_dns(address: str) -> str | None:
    """Attempt to resolve an IP address to a hostname."""

    try:
        hostname, _, _ = socket.gethostbyaddr(address)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def get_ip_info(target: str) -> IPInfoResult:
    """Collect basic information about an IP address."""

    address = resolve_target(target)

    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {address}") from exc

    return IPInfoResult(
        address=address,
        version=f"IPv{ip.version}",
        is_private=ip.is_private,
        is_loopback=ip.is_loopback,
        is_reserved=ip.is_reserved,
        is_multicast=ip.is_multicast,
        reverse_dns=get_reverse_dns(address),
    )
