"""Command-line interface for VoidScan."""

import argparse
import sys

from voidscan import __version__
from voidscan.menu import run_menu


def build_parser() -> argparse.ArgumentParser:
    """Build the VoidScan argument parser."""

    parser = argparse.ArgumentParser(
        prog="voidscan",
        description="Authorized reconnaissance and security assessment toolkit.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    """Run the VoidScan command-line interface."""

    parser = build_parser()

    if argv is None:
        argv = sys.argv[1:]

    parser.parse_args(argv)

    run_menu()


if __name__ == "__main__":
    main()