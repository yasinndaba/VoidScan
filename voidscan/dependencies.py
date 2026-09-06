"""External tool dependency checks for VoidScan."""

import shutil


REQUIRED_TOOLS = (
    "nmap",
    "ffuf",
    "dirb",
    "subfinder",
    "amass",
)


def is_tool_installed(tool: str) -> bool:
    """Return True when an external tool is available in PATH."""

    return shutil.which(tool) is not None


def get_missing_tools() -> list[str]:
    """Return external tools that are not installed."""

    return [
        tool
        for tool in REQUIRED_TOOLS
        if not is_tool_installed(tool)
    ]
