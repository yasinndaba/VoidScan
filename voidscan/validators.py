"""Validation helpers for VoidScan targets."""

import ipaddress
import re


HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"\.)+"
    r"[a-zA-Z]{2,63}$"
)


def is_valid_ip(target: str) -> bool:
    """Return True when target is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_valid_hostname(target: str) -> bool:
    """Return True when target is a valid hostname or domain."""
    return bool(HOSTNAME_PATTERN.fullmatch(target))


def is_valid_target(target: str) -> bool:
    """Return True when target is a valid IP address or hostname."""
    target = target.strip()

    if not target:
        return False

    return is_valid_ip(target) or is_valid_hostname(target)
