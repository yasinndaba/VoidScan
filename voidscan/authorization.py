"""Session-wide authorization state for VoidScan scans.

VoidScan asks for explicit authorization before the first scan in a
process. Later scans in the same session inherit that confirmation.
"""

from __future__ import annotations

_authorized = False


def is_authorized() -> bool:
    """Return True when the session has already been authorized."""

    return _authorized


def mark_authorized() -> None:
    """Record that the user confirmed authorization for this session."""

    global _authorized
    _authorized = True


def reset_authorization() -> None:
    """Clear the session authorization state. Intended for tests."""

    global _authorized
    _authorized = False
