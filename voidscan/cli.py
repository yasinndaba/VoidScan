"""Command-line interface for VoidScan."""

import argparse
import sys

from rich.console import Console
from rich.panel import Panel

from voidscan import __version__
from voidscan.config import Config
from voidscan.dependencies import get_missing_tools
from voidscan.logger import setup_logger
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


def warn_missing_tools(missing: list[str]) -> None:
    """Display a startup warning when external tools are missing."""

    if not missing:
        return

    lines = "\n".join(f"  • {tool}" for tool in missing)

    Console().print(
        Panel(
            "[bold yellow]Some external tools are missing:[/bold yellow]\n"
            f"{lines}\n\n"
            "[dim]Features that depend on these tools will fail until "
            "they are installed.[/dim]",
            title="Dependency Warning",
            border_style="yellow",
        )
    )


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]

    parser.parse_args(argv)

    config = Config()
    config.create_directories()

    logger = setup_logger(config.log_dir)
    logger.info("VoidScan %s session started", __version__)

    warn_missing_tools(get_missing_tools())

    try:
        run_menu()
    except (KeyboardInterrupt, EOFError):
        logger.info("VoidScan session ended by user")
        print("\n\nVoidScan Session Ended.")
    finally:
        logger.info("VoidScan session finished")


if __name__ == "__main__":
    main()
