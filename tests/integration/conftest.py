"""Fixtures for end-to-end integration tests.

The tests use fake external tools placed first on ``PATH`` and a local
HTTP server bound to loopback, so they never touch the internet.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest


class _QuietHandler(SimpleHTTPRequestHandler):
    """Serve files without writing request logs to stderr."""

    def log_message(self, *args: object) -> None:
        return


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point ``HOME`` at a temporary directory."""

    home = tmp_path / "home"
    home.mkdir()

    monkeypatch.setenv("HOME", str(home))

    return home


@pytest.fixture
def fake_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    isolated_home: Path,
) -> Path:
    """Create deterministic stand-ins for every external tool."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()

    _write_executable(
        bin_dir / "nmap",
        """#!/bin/sh
xml=0
target=""
for arg in "$@"; do
  if [ "$arg" = "-oX" ]; then xml=1; fi
  target="$arg"
done
if [ "$xml" = "1" ]; then
cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
<host><status state="up"/><ports>
<port protocol="tcp" portid="22">
  <state state="open"/>
  <service name="ssh" product="OpenSSH" version="8.9p1"
           extrainfo="Ubuntu"/>
</port>
<port protocol="tcp" portid="80">
  <state state="open"/>
  <service name="http" product="nginx" version="1.24.0"/>
</port>
<port protocol="tcp" portid="443">
  <state state="filtered"/>
  <service name="https"/>
</port>
</ports></host>
</nmaprun>
EOF
else
cat <<EOF
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for $target
Host is up (0.00020s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp open  http    nginx 1.24.0
443/tcp filtered https

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
EOF
fi
""",
    )

    _write_executable(
        bin_dir / "ping",
        """#!/bin/sh
last=""
for arg in "$@"; do last="$arg"; done
case "$last" in
  192.168.50.1|192.168.50.2) exit 0 ;;
  *) exit 1 ;;
esac
""",
    )

    _write_executable(
        bin_dir / "subfinder",
        """#!/bin/sh
cat <<'EOF'
{"host":"www.example.com","source":"crtsh"}
{"host":"api.example.com","source":"crtsh"}
{"host":"www.example.com","source":"dnsdumpster"}
not a hostname
EOF
""",
    )

    _write_executable(
        bin_dir / "amass",
        """#!/bin/sh
cat <<'EOF'
OWASP Amass v4.2.0
[INF] Starting passive enumeration
mail.example.com
vpn.example.com
EOF
""",
    )

    _write_executable(
        bin_dir / "ffuf",
        f"""#!{sys.executable}
import json
import sys
import urllib.request

args = sys.argv[1:]
url = args[args.index("-u") + 1]
wordlist = args[args.index("-w") + 1]

with open(wordlist, encoding="utf-8") as handle:
    words = [line.strip() for line in handle if line.strip()]

for word in words:
    candidate = url.replace("FUZZ", word)

    try:
        with urllib.request.urlopen(candidate, timeout=2) as response:
            if response.status < 500:
                payload = {{"url": candidate, "status": response.status}}
                print(json.dumps(payload))
    except Exception:
        continue
""",
    )

    _write_executable(
        bin_dir / "dirb",
        f"""#!{sys.executable}
import sys
import urllib.request

target = sys.argv[1].rstrip("/")
wordlist = sys.argv[2]

with open(wordlist, encoding="utf-8") as handle:
    words = [line.strip() for line in handle if line.strip()]

for word in words:
    candidate = f"{{target}}/{{word}}"

    try:
        with urllib.request.urlopen(candidate, timeout=2) as response:
            if response.status < 500:
                print(f"+ {{candidate}}")
    except Exception:
        continue
""",
    )

    monkeypatch.setenv(
        "PATH",
        f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
    )

    return bin_dir


@pytest.fixture
def local_site(tmp_path: Path) -> Iterator[str]:
    """Serve a small website from loopback and yield its base URL."""

    docroot = tmp_path / "site"
    (docroot / "admin").mkdir(parents=True)
    (docroot / "admin" / "index.html").write_text(
        "admin console",
        encoding="utf-8",
    )
    (docroot / "login").mkdir()
    (docroot / "login" / "index.html").write_text(
        "login form",
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
