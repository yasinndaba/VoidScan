"""Validation helpers for VoidScan targets."""

import ipaddress
import re
from urllib.parse import urlparse


_LABEL_PATTERN = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)

_TLD_PATTERN = re.compile(
    r"^(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9-]{1,59})$"
)

WEB_SCHEMES = {"http", "https"}


def is_valid_ip(target: str) -> bool:
    """Return True when target is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_valid_hostname(target: str) -> bool:
    """Return True when target is a valid hostname or domain.

    Single-label hostnames such as ``localhost`` are accepted so local
    laboratories can be used. Multi-label names require a valid top-level
    domain, which rejects numeric lookalikes such as ``999.999.999.999``.
    """

    target = target.strip().rstrip(".")

    if not target or len(target) > 253:
        return False

    labels = target.split(".")

    if any(not _LABEL_PATTERN.fullmatch(label) for label in labels):
        return False

    if len(labels) == 1:
        return any(character.isalpha() for character in labels[0])

    return bool(_TLD_PATTERN.fullmatch(labels[-1]))


def is_valid_web_url(target: str) -> bool:
    """Return True when target is a valid HTTP or HTTPS URL."""

    target = target.strip()

    if not target or any(character.isspace() for character in target):
        return False

    try:
        parsed = urlparse(target)
    except ValueError:
        return False

    if parsed.scheme.lower() not in WEB_SCHEMES:
        return False

    if not parsed.netloc or parsed.username or parsed.password:
        return False

    host = parsed.hostname

    if not host:
        return False

    try:
        port = parsed.port
    except ValueError:
        return False

    if port is not None and not 1 <= port <= 65535:
        return False

    return is_valid_ip(host) or is_valid_hostname(host)


def is_valid_target(target: str) -> bool:
    """Return True when target is an IP, hostname, or HTTP(S) URL."""

    target = target.strip()

    if not target:
        return False

    return (
        is_valid_ip(target)
        or is_valid_hostname(target)
        or is_valid_web_url(target)
    )


def target_host(target: str) -> str:
    """Return the host portion of a target, stripping any web URL."""

    target = target.strip()

    if is_valid_web_url(target):
        return urlparse(target).hostname or target

    return target


def to_web_url(target: str) -> str:
    """Return a usable web URL for a target.

    URLs are returned unchanged. Bare IP addresses and hostnames are
    promoted to ``http://`` URLs so directory enumeration can be used
    without storing a full URL.
    """

    target = target.strip()

    if is_valid_web_url(target):
        return target

    if is_valid_ip(target) or is_valid_hostname(target):
        return f"http://{target}"

    raise ValueError(f"Invalid web target: {target}")
