"""Optional tests that exercise the real external tools.

These tests are skipped by default. Run them on a machine with the tools
installed and network access with:

    pytest -m live
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from voidscan.scanners.directories import enumerate_directories
from voidscan.scanners.nmap import run_nmap
from voidscan.scanners.subdomains import run_subfinder

pytestmark = pytest.mark.live


class _QuietHandler(SimpleHTTPRequestHandler):
    """Serve files without writing request logs to stderr."""

    def log_message(self, *args: object) -> None:
        return


@pytest.fixture
def local_site(tmp_path: Path) -> Iterator[str]:
    """Serve a small website from loopback and yield its base URL."""

    docroot = tmp_path / "site"
    (docroot / "admin").mkdir(parents=True)
    (docroot / "admin" / "index.html").write_text(
        "admin console",
        encoding="utf-8",
    )

    handler = partial(_QuietHandler, directory=str(docroot))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    host, port = server.server_address[:2]

    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed")
def test_live_nmap_loopback() -> None:
    result = run_nmap("127.0.0.1", "quick", timeout=120)

    assert result.success
    assert result.command[0] == "nmap"
    assert "-oX" in result.command


@pytest.mark.parametrize("engine", ["ffuf", "dirb"])
def test_live_directory_enumeration(
    engine: str,
    local_site: str,
    tmp_path: Path,
) -> None:
    if shutil.which(engine) is None:
        pytest.skip(f"{engine} not installed")

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nmissing\n", encoding="utf-8")

    result = enumerate_directories(
        local_site,
        engine,
        wordlist,
        timeout=120,
    )

    assert result.success
    assert any(url.rstrip("/").endswith("/admin") for url in result.results)


@pytest.mark.skipif(
    shutil.which("subfinder") is None,
    reason="subfinder not installed",
)
def test_live_subfinder_example_com() -> None:
    result = run_subfinder("example.com", timeout=120)

    assert result.success
    assert result.domain == "example.com"
