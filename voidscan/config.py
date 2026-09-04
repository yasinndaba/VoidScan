"""Application configuration for VoidScan."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    """Global VoidScan configuration."""

    data_dir: Path = Path.home() / ".voidscan"
    log_dir: Path = Path.home() / ".voidscan" / "logs"
    report_dir: Path = Path.home() / ".voidscan" / "reports"
    target_file: Path = Path.home() / ".voidscan" / "targets.txt"

    def create_directories(self) -> None:
        """Create required VoidScan directories."""

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)