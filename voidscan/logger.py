"""Logging configuration for VoidScan."""

import logging
from pathlib import Path


def setup_logger(log_directory: Path) -> logging.Logger:
    """Create and configure the VoidScan logger."""

    log_directory.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("voidscan")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    log_file = log_directory / "voidscan.log"

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
