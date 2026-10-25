"""Command-line interface for VoidScan."""

import argparse
import os
import sys
from dataclasses import replace
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from voidscan import __version__
from voidscan.config import (
    Config,
    apply_env_overrides,
    load_config,
    set_config,
    with_data_dir,
)
from voidscan.dependencies import get_missing_tools
from voidscan.logger import setup_logger
from voidscan.menu import run_menu


def build_parser() -> argparse.ArgumentParser:
    """Build the VoidScan argument parser."""

    parser = argparse.ArgumentParser(
        prog="voidscan",
        description=(
            "Authorized reconnaissance and security assessment toolkit."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    parser.add_argument(
        "--config",
        type=Path,
        metavar="PATH",
        help=(
            "Load configuration from PATH instead of ~/.voidscan/config.toml."
        ),
    )

    parser.add_argument(
        "--data-dir",
        type=Path,
        metavar="PATH",
        help="Store data, logs, reports, and targets under PATH.",
    )

    parser.add_argument(
        "--log-dir",
        type=Path,
        metavar="PATH",
        help="Write logs to PATH.",
    )

    parser.add_argument(
        "--report-dir",
        type=Path,
        metavar="PATH",
        help="Write reports to PATH.",
    )

    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the first-scan authorization confirmation.",
    )

    return parser


def _apply_cli_overrides(
    config: Config,
    args: argparse.Namespace,
) -> Config:
    """Apply command-line path overrides after config and environment."""

    if args.data_dir is not None:
        config = with_data_dir(config, args.data_dir)

    if args.log_dir is not None:
        config = replace(
            config,
            log_dir=Path(args.log_dir).expanduser(),
        )

    if args.report_dir is not None:
        config = replace(
            config,
            report_dir=Path(args.report_dir).expanduser(),
        )

    if args.yes:
        config = replace(config, assume_yes=True)

    return config


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


def warn_config_issues(warnings: list[str]) -> None:
    """Display configuration warnings without stopping startup."""

    if not warnings:
        return

    lines = "\n".join(f"  • {warning}" for warning in warnings)

    Console().print(
        Panel(
            "[bold yellow]Some settings could not be loaded:[/bold yellow]\n"
            f"{lines}\n\n"
            "[dim]VoidScan is using safe defaults for those settings.[/dim]",
            title="Configuration Warning",
            border_style="yellow",
        )
    )


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]

    args = parser.parse_args(argv)

    config_path = args.config or os.environ.get("VOIDSCAN_CONFIG")
    config, config_warnings = load_config(config_path)
    config = apply_env_overrides(config, config_warnings)
    config = _apply_cli_overrides(config, args)
    config.create_directories()

    set_config(config)

    logger = setup_logger(config.log_dir)
    logger.info("VoidScan %s session started", __version__)
    logger.info("Using configuration file: %s", config.config_file)

    warn_config_issues(config_warnings)
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
