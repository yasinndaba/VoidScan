"""Shared exceptions for VoidScan scan execution."""


class ScanCancelled(Exception):
    """Raised when the user cancels an active scan."""


class ScanTimeout(RuntimeError):
    """Raised when an external tool exceeds its configured timeout."""

    def __init__(
        self,
        message: str,
        *,
        timeout: float | None = None,
        stdout: str = "",
        stderr: str = "",
        return_code: int = -1,
    ) -> None:
        super().__init__(message)
        self.timeout = timeout
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code
