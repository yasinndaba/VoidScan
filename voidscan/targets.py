"""Target management for VoidScan."""

from dataclasses import dataclass
from pathlib import Path

from voidscan.validators import is_valid_target


@dataclass(frozen=True)
class Target:
    """Represent a validated VoidScan target."""

    value: str

    def __post_init__(self) -> None:
        if not is_valid_target(self.value):
            raise ValueError(f"Invalid target: {self.value}")


class TargetManager:
    """Manage persistent VoidScan targets."""

    def __init__(self, target_file: Path) -> None:
        self.target_file = target_file
        self.target_file.parent.mkdir(parents=True, exist_ok=True)

    def list_targets(self) -> list[str]:
        """Return all saved targets."""

        if not self.target_file.exists():
            return []

        return [
            line.strip()
            for line in self.target_file.read_text().splitlines()
            if line.strip()
        ]

    def add_target(self, target: str) -> bool:
        """Add a valid target if it does not already exist."""

        target = target.strip()

        validated = Target(target)

        targets = self.list_targets()

        if validated.value in targets:
            return False

        with self.target_file.open("a") as file:
            file.write(f"{validated.value}\n")

        return True

    def remove_target(self, target: str) -> bool:
        """Remove a target from the saved target list."""

        targets = self.list_targets()

        if target not in targets:
            return False

        targets.remove(target)

        self.target_file.write_text(
            "\n".join(targets) + ("\n" if targets else "")
        )

        return True

    def clear_targets(self) -> None:
        """Remove all saved targets."""

        self.target_file.write_text("")