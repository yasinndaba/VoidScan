"""Coverage-oriented tests for the interactive menu flows."""

import json
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from voidscan import menu
from voidscan.config import Config
from voidscan.errors import ScanCancelled, ScanTimeout
from voidscan.execution import ScanContext
from voidscan.scanners.directories import DirectoryResult
from voidscan.scanners.discovery import HostDiscoveryResult
from voidscan.scanners.ip_info import IPInfoResult
from voidscan.scanners.nmap import NmapResult
from voidscan.scanners.subdomains import SubdomainResult
from voidscan.scanners.system_monitor import SystemMonitorResult


def make_config(tmp_path: Path) -> Config:
    """Build an isolated configuration rooted in a temporary directory."""

    return Config(
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
        report_dir=tmp_path / "reports",
        target_file=tmp_path / "targets.txt",
    )


def run_immediately(description, operation, console=None):
    """Run a scan operation inline instead of on a worker thread."""

    return operation(ScanContext(description=description))


@contextmanager
def menu_harness(
    tmp_path: Path,
    *,
    targets: Sequence[str] = ("127.0.0.1",),
    prompts: Sequence[str] = (),
    confirms: Sequence[bool] = (),
    inputs: Sequence[str] | None = None,
    progress=run_immediately,
):
    """Patch menu input and configuration for one flow execution."""

    config = make_config(tmp_path)
    manager = MagicMock()
    manager.list_targets.return_value = list(targets)
    manager.add_target.return_value = True
    manager.remove_target.return_value = True

    if inputs is None:
        input_patch = patch("voidscan.menu.console.input", return_value="")
    else:
        input_patch = patch(
            "voidscan.menu.console.input",
            side_effect=list(inputs),
        )

    with (
        patch("voidscan.menu.get_config", return_value=config),
        patch("voidscan.menu.TargetManager", return_value=manager),
        patch(
            "voidscan.menu.require_authorization",
            return_value=True,
        ),
        patch("voidscan.menu.Prompt.ask", side_effect=list(prompts)),
        patch("voidscan.menu.Confirm.ask", side_effect=list(confirms)),
        input_patch,
        patch("voidscan.menu.show_banner"),
        patch("voidscan.menu.run_with_progress", side_effect=progress),
    ):
        yield config, manager


def make_nmap_result(*, success: bool = True) -> NmapResult:
    return NmapResult(
        target="127.0.0.1",
        command=["nmap", "127.0.0.1"],
        output="22/tcp open ssh",
        return_code=0 if success else 1,
        success=success,
    )


def make_discovery_result(
    hosts: Sequence[str] = ("192.168.1.1",),
) -> HostDiscoveryResult:
    return HostDiscoveryResult(
        network="192.168.1.0/24",
        hosts=list(hosts),
        scanned=254,
        reachable=len(hosts),
        command=["ping", "-c", "1", "-W", "1", "<host>"],
    )


def make_subdomain_result(
    *,
    subdomains: Sequence[str] = ("www.example.com",),
    engine: str = "subfinder",
    success: bool = True,
    timed_out: bool = False,
    return_code: int = 0,
) -> SubdomainResult:
    return SubdomainResult(
        domain="example.com",
        engine=engine,
        subdomains=list(subdomains),
        return_code=return_code,
        success=success,
        timed_out=timed_out,
    )


def make_directory_result(
    *,
    results: Sequence[str] = ("http://example.com/admin",),
    success: bool = True,
) -> DirectoryResult:
    return DirectoryResult(
        target="http://example.com",
        engine="ffuf",
        wordlist="common.txt",
        results=list(results),
        return_code=0 if success else 1,
        success=success,
    )


def make_ip_result(*, reverse_dns: str | None = None) -> IPInfoResult:
    return IPInfoResult(
        address="93.184.216.34",
        version="4",
        is_private=False,
        is_loopback=False,
        is_reserved=False,
        is_multicast=False,
        reverse_dns=reverse_dns,
    )


def make_system_result() -> SystemMonitorResult:
    return SystemMonitorResult(
        hostname="voidscan-test",
        operating_system="Linux",
        kernel="6.0.0",
        architecture="x86_64",
        cpu_count=4,
        memory_total_gb=8.0,
        memory_available_gb=4.0,
        disk_total_gb=100.0,
        disk_free_gb=50.0,
        uptime_seconds=90061.0,
    )


# Target Manager


def test_target_manager_adds_lists_and_removes(tmp_path):
    with menu_harness(
        tmp_path,
        prompts=["1", "example.com", "2", "3", "example.com", "5"],
        confirms=(),
    ) as (_, manager):
        menu.target_manager()

    manager.add_target.assert_called_once_with("example.com")
    manager.remove_target.assert_called_once_with("example.com")
    manager.list_targets.assert_called()


def test_target_manager_reports_duplicate_and_invalid_targets(tmp_path):
    with menu_harness(
        tmp_path,
        prompts=["1", "example.com", "1", "bad target", "5"],
    ) as (_, manager):
        manager.add_target.side_effect = [False, ValueError("invalid")]
        menu.target_manager()


def test_target_manager_reports_missing_remove_and_clear(tmp_path):
    with menu_harness(
        tmp_path,
        targets=(),
        prompts=["2", "3", "4", "5"],
    ) as (_, manager):
        menu.target_manager()

    manager.remove_target.assert_not_called()
    manager.clear_targets.assert_not_called()


def test_target_manager_clears_targets_when_confirmed(tmp_path):
    with menu_harness(
        tmp_path,
        prompts=["4", "5"],
        confirms=(True,),
    ) as (_, manager):
        menu.target_manager()

    manager.clear_targets.assert_called_once()


def test_target_manager_keeps_targets_when_clear_is_declined(tmp_path):
    with menu_harness(
        tmp_path,
        prompts=["4", "5"],
        confirms=(False,),
    ) as (_, manager):
        menu.target_manager()

    manager.clear_targets.assert_not_called()


# Network scan


def test_network_scan_without_targets(tmp_path):
    with menu_harness(tmp_path, targets=()):
        menu.network_scan()


def test_network_scan_can_cancel_target_and_profile(tmp_path):
    with menu_harness(tmp_path, prompts=["0", "1", "0"]):
        menu.network_scan()


def test_network_scan_reports_a_failed_scan(tmp_path):
    with (
        menu_harness(tmp_path, prompts=["1", "1"]),
        patch(
            "voidscan.menu.run_nmap",
            return_value=make_nmap_result(success=False),
        ),
    ):
        menu.network_scan()


def test_network_scan_handles_cancellation(tmp_path):
    with (
        menu_harness(
            tmp_path,
            prompts=["1", "1"],
            progress=MagicMock(side_effect=ScanCancelled("cancelled")),
        ),
    ):
        menu.network_scan()


def test_network_scan_handles_timeout(tmp_path):
    with (
        menu_harness(
            tmp_path,
            prompts=["1", "1"],
            progress=MagicMock(side_effect=ScanTimeout("timed out")),
        ),
    ):
        menu.network_scan()


def test_network_scan_handles_scan_errors(tmp_path):
    with (
        menu_harness(
            tmp_path,
            prompts=["1", "1"],
            progress=MagicMock(side_effect=RuntimeError("scan failed")),
        ),
    ):
        menu.network_scan()


def test_network_scan_reports_save_errors(tmp_path):
    with (
        menu_harness(tmp_path, prompts=["1", "1"], confirms=(True, True)),
        patch("voidscan.menu.run_nmap", return_value=make_nmap_result()),
        patch("voidscan.menu.save_json_report", side_effect=OSError("disk")),
        patch("voidscan.menu.save_html_report", side_effect=OSError("disk")),
    ):
        menu.network_scan()


# Live host discovery


def test_live_host_discovery_rejects_an_empty_network(tmp_path):
    with menu_harness(tmp_path, prompts=[""]):
        menu.live_host_discovery()


def test_live_host_discovery_rejects_an_invalid_network(tmp_path):
    with menu_harness(tmp_path, prompts=["not-a-network"]):
        menu.live_host_discovery()


def test_live_host_discovery_rejects_an_oversized_network(tmp_path):
    with (
        menu_harness(tmp_path, prompts=["10.0.0.0/8"]),
        patch("voidscan.menu.discover_hosts") as discovery,
    ):
        menu.live_host_discovery()

    discovery.assert_not_called()


def test_live_host_discovery_reports_hosts_and_saves_reports(tmp_path):
    hosts = [f"192.168.1.{index}" for index in range(1, 61)]

    with (
        menu_harness(
            tmp_path,
            prompts=["192.168.1.0/24"],
            confirms=(True, True),
        ),
        patch(
            "voidscan.menu.discover_hosts",
            return_value=make_discovery_result(hosts),
        ),
    ):
        menu.live_host_discovery()

    assert (
        len(list((tmp_path / "reports").glob("live_host_discovery_*.json")))
        == 1
    )

    report_path = next(
        (tmp_path / "reports").glob("live_host_discovery_*.json")
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["audit"]["result_count"] == len(hosts)
    assert report["audit"]["command"].startswith("ping -c 1")
    assert report["audit"]["duration_seconds"] >= 0
    assert report["audit"]["started_at"] <= report["audit"]["finished_at"]


def test_live_host_discovery_reports_no_hosts(tmp_path):
    with (
        menu_harness(
            tmp_path,
            prompts=["192.168.1.0/24"],
            confirms=(False, False),
        ),
        patch(
            "voidscan.menu.discover_hosts",
            return_value=make_discovery_result(()),
        ),
    ):
        menu.live_host_discovery()


def test_live_host_discovery_handles_cancellation(tmp_path):
    with menu_harness(
        tmp_path,
        prompts=["192.168.1.0/24"],
        progress=MagicMock(side_effect=ScanCancelled("cancelled")),
    ):
        menu.live_host_discovery()


def test_live_host_discovery_handles_errors(tmp_path):
    with menu_harness(
        tmp_path,
        prompts=["192.168.1.0/24"],
        progress=MagicMock(side_effect=RuntimeError("discovery failed")),
    ):
        menu.live_host_discovery()


def test_live_host_discovery_reports_save_errors(tmp_path):
    with (
        menu_harness(
            tmp_path,
            prompts=["192.168.1.0/24"],
            confirms=(True, True),
        ),
        patch(
            "voidscan.menu.discover_hosts",
            return_value=make_discovery_result(),
        ),
        patch("voidscan.menu.save_json_report", side_effect=OSError("disk")),
        patch("voidscan.menu.save_html_report", side_effect=OSError("disk")),
    ):
        menu.live_host_discovery()


# Subdomain enumeration


def test_subdomain_enumeration_without_targets(tmp_path):
    with menu_harness(tmp_path, targets=()):
        menu.subdomain_enumeration()


def test_subdomain_enumeration_can_cancel_target_and_engine(tmp_path):
    with menu_harness(tmp_path, prompts=["0", "1", "0"]):
        menu.subdomain_enumeration()


def test_subdomain_enumeration_rejects_an_invalid_domain(tmp_path):
    with menu_harness(tmp_path, targets=("bad target",), prompts=["1"]):
        menu.subdomain_enumeration()


def test_subdomain_enumeration_reports_results_and_saves(tmp_path):
    with (
        menu_harness(
            tmp_path,
            targets=("example.com",),
            prompts=["1", "1"],
            confirms=(True, True),
        ),
        patch(
            "voidscan.menu.enumerate_subdomains",
            return_value=make_subdomain_result(),
        ),
    ):
        menu.subdomain_enumeration()

    assert (
        len(list((tmp_path / "reports").glob("subdomain_enumeration_*.json")))
        == 1
    )


def test_subdomain_enumeration_reports_empty_success(tmp_path):
    with (
        menu_harness(
            tmp_path,
            targets=("example.com",),
            prompts=["1", "1"],
            confirms=(False, False),
        ),
        patch(
            "voidscan.menu.enumerate_subdomains",
            return_value=make_subdomain_result(subdomains=()),
        ),
    ):
        menu.subdomain_enumeration()


def test_subdomain_enumeration_reports_a_failed_engine(tmp_path):
    with (
        menu_harness(
            tmp_path,
            targets=("example.com",),
            prompts=["1", "1"],
        ),
        patch(
            "voidscan.menu.enumerate_subdomains",
            return_value=make_subdomain_result(
                subdomains=(),
                success=False,
                return_code=2,
            ),
        ),
    ):
        menu.subdomain_enumeration()


def test_subdomain_enumeration_retries_amass_with_subfinder(tmp_path):
    amass = make_subdomain_result(
        subdomains=("api.example.com",),
        engine="amass",
        success=False,
        timed_out=True,
    )
    subfinder = make_subdomain_result(subdomains=("www.example.com",))

    with (
        menu_harness(
            tmp_path,
            targets=("example.com",),
            prompts=["1", "2"],
            confirms=(True, True, True),
        ),
        patch(
            "voidscan.menu.enumerate_subdomains",
            side_effect=[amass, subfinder],
        ),
    ):
        menu.subdomain_enumeration()


def test_subdomain_enumeration_reports_amass_timeout_without_retry(tmp_path):
    with (
        menu_harness(
            tmp_path,
            targets=("example.com",),
            prompts=["1", "2"],
            confirms=(False, False, False),
        ),
        patch(
            "voidscan.menu.enumerate_subdomains",
            return_value=make_subdomain_result(
                subdomains=(),
                engine="amass",
                success=False,
                timed_out=True,
            ),
        ),
    ):
        menu.subdomain_enumeration()


def test_subdomain_enumeration_handles_retry_cancellation(tmp_path):
    amass = make_subdomain_result(
        engine="amass",
        success=False,
        timed_out=True,
    )

    progress = MagicMock(
        side_effect=[
            amass,
            ScanCancelled("cancelled"),
        ]
    )

    with menu_harness(
        tmp_path,
        targets=("example.com",),
        prompts=["1", "2"],
        confirms=(True,),
        progress=progress,
    ):
        menu.subdomain_enumeration()


def test_subdomain_enumeration_handles_retry_errors(tmp_path):
    amass = make_subdomain_result(
        engine="amass",
        success=False,
        timed_out=True,
    )

    progress = MagicMock(
        side_effect=[
            amass,
            RuntimeError("subfinder failed"),
        ]
    )

    with menu_harness(
        tmp_path,
        targets=("example.com",),
        prompts=["1", "2"],
        confirms=(True, False, False),
        progress=progress,
    ):
        menu.subdomain_enumeration()


def test_subdomain_enumeration_handles_cancellation(tmp_path):
    with menu_harness(
        tmp_path,
        targets=("example.com",),
        prompts=["1", "1"],
        progress=MagicMock(side_effect=ScanCancelled("cancelled")),
    ):
        menu.subdomain_enumeration()


def test_subdomain_enumeration_handles_errors(tmp_path):
    with menu_harness(
        tmp_path,
        targets=("example.com",),
        prompts=["1", "1"],
        progress=MagicMock(side_effect=RuntimeError("enumeration failed")),
    ):
        menu.subdomain_enumeration()


def test_subdomain_enumeration_reports_save_errors(tmp_path):
    with (
        menu_harness(
            tmp_path,
            targets=("example.com",),
            prompts=["1", "1"],
            confirms=(True, True),
        ),
        patch(
            "voidscan.menu.enumerate_subdomains",
            return_value=make_subdomain_result(),
        ),
        patch("voidscan.menu.save_json_report", side_effect=OSError("disk")),
        patch("voidscan.menu.save_html_report", side_effect=OSError("disk")),
    ):
        menu.subdomain_enumeration()


# Directory enumeration


def test_directory_enumeration_without_targets(tmp_path):
    with menu_harness(tmp_path, targets=()):
        menu.directory_enumeration()


def test_directory_enumeration_can_cancel_steps(tmp_path):
    with menu_harness(tmp_path, prompts=["0", "1", "0", "1", "1", "0"]):
        menu.directory_enumeration()


def test_directory_enumeration_rejects_an_invalid_target(tmp_path):
    with menu_harness(tmp_path, targets=("bad target",), prompts=["1"]):
        menu.directory_enumeration()


def test_directory_enumeration_requires_a_custom_wordlist(tmp_path):
    with menu_harness(tmp_path, prompts=["1", "1", "2", ""]):
        menu.directory_enumeration()


def test_directory_enumeration_uses_the_default_wordlist(tmp_path):
    with (
        menu_harness(
            tmp_path,
            targets=("example.com",),
            prompts=["1", "1", "1"],
            confirms=(True, True),
        ),
        patch(
            "voidscan.menu.enumerate_directories",
            return_value=make_directory_result(),
        ),
    ):
        menu.directory_enumeration()

    assert (
        len(list((tmp_path / "reports").glob("directory_enumeration_*.json")))
        == 1
    )


def test_directory_enumeration_uses_a_custom_wordlist(tmp_path):
    with (
        menu_harness(
            tmp_path,
            targets=("example.com",),
            prompts=["1", "2", "2", "/tmp/words.txt"],
            confirms=(False, False),
        ),
        patch(
            "voidscan.menu.enumerate_directories",
            return_value=make_directory_result(),
        ) as enumerate_directories,
    ):
        menu.directory_enumeration()

    assert enumerate_directories.call_args.args[2] == "/tmp/words.txt"


def test_directory_enumeration_reports_no_results(tmp_path):
    with (
        menu_harness(
            tmp_path,
            targets=("example.com",),
            prompts=["1", "1", "1"],
            confirms=(False, False),
        ),
        patch(
            "voidscan.menu.enumerate_directories",
            return_value=make_directory_result(results=()),
        ),
    ):
        menu.directory_enumeration()


def test_directory_enumeration_reports_a_failed_engine(tmp_path):
    with (
        menu_harness(
            tmp_path,
            targets=("example.com",),
            prompts=["1", "1", "1"],
        ),
        patch(
            "voidscan.menu.enumerate_directories",
            return_value=make_directory_result(success=False),
        ),
    ):
        menu.directory_enumeration()


def test_directory_enumeration_handles_cancellation(tmp_path):
    with menu_harness(
        tmp_path,
        targets=("example.com",),
        prompts=["1", "1", "1"],
        progress=MagicMock(side_effect=ScanCancelled("cancelled")),
    ):
        menu.directory_enumeration()


def test_directory_enumeration_handles_errors(tmp_path):
    with menu_harness(
        tmp_path,
        targets=("example.com",),
        prompts=["1", "1", "1"],
        progress=MagicMock(side_effect=RuntimeError("enumeration failed")),
    ):
        menu.directory_enumeration()


def test_directory_enumeration_reports_save_errors(tmp_path):
    with (
        menu_harness(
            tmp_path,
            targets=("example.com",),
            prompts=["1", "1", "1"],
            confirms=(True, True),
        ),
        patch(
            "voidscan.menu.enumerate_directories",
            return_value=make_directory_result(),
        ),
        patch("voidscan.menu.save_json_report", side_effect=OSError("disk")),
        patch("voidscan.menu.save_html_report", side_effect=OSError("disk")),
    ):
        menu.directory_enumeration()


# IP information


def test_ip_information_without_targets(tmp_path):
    with menu_harness(tmp_path, targets=()):
        menu.ip_information()


def test_ip_information_can_cancel_target_selection(tmp_path):
    with menu_harness(tmp_path, prompts=["0"]):
        menu.ip_information()


def test_ip_information_displays_and_saves(tmp_path):
    with (
        menu_harness(tmp_path, prompts=["1"], confirms=(True, True)),
        patch(
            "voidscan.menu.get_ip_info",
            return_value=make_ip_result(reverse_dns="example.com"),
        ),
    ):
        menu.ip_information()

    assert len(list((tmp_path / "reports").glob("ip_information_*.json"))) == 1


def test_ip_information_handles_resolution_errors(tmp_path):
    with (
        menu_harness(tmp_path, prompts=["1"]),
        patch(
            "voidscan.menu.get_ip_info",
            side_effect=ValueError("Could not resolve target"),
        ),
    ):
        menu.ip_information()


def test_ip_information_reports_save_errors(tmp_path):
    with (
        menu_harness(tmp_path, prompts=["1"], confirms=(True, True)),
        patch("voidscan.menu.get_ip_info", return_value=make_ip_result()),
        patch("voidscan.menu.save_json_report", side_effect=OSError("disk")),
        patch("voidscan.menu.save_html_report", side_effect=OSError("disk")),
    ):
        menu.ip_information()


# System monitor and logs


def test_system_monitor_displays_information(tmp_path):
    with (
        menu_harness(tmp_path),
        patch(
            "voidscan.menu.get_system_monitor",
            return_value=make_system_result(),
        ),
    ):
        menu.system_monitor()


def test_system_monitor_handles_errors(tmp_path):
    with (
        menu_harness(tmp_path),
        patch(
            "voidscan.menu.get_system_monitor",
            side_effect=RuntimeError("cannot read /proc"),
        ),
    ):
        menu.system_monitor()


def test_view_logs_without_a_log_file(tmp_path):
    with menu_harness(tmp_path):
        menu.view_logs()


def test_view_logs_previews_recent_entries(tmp_path):
    config = make_config(tmp_path)
    config.create_directories()
    log_file = config.log_dir / "voidscan.log"
    log_file.write_text(
        "\n".join(f"entry {index}" for index in range(100)),
        encoding="utf-8",
    )

    with menu_harness(tmp_path):
        menu.view_logs()


# Settings


def test_settings_displays_configuration_and_tool_status(tmp_path):
    with (
        menu_harness(tmp_path),
        patch(
            "voidscan.menu.is_tool_installed",
            side_effect=[True, False, True, False, True],
        ),
    ):
        menu.settings()


# Main menu


def test_run_menu_exits(tmp_path):
    with menu_harness(tmp_path, inputs=["0"]):
        menu.run_menu()


def test_run_menu_reports_an_invalid_option(tmp_path):
    with menu_harness(tmp_path, inputs=["nope", "", "0"]):
        menu.run_menu()


def test_run_menu_dispatches_every_flow(tmp_path):
    names = [
        "network_scan",
        "live_host_discovery",
        "subdomain_enumeration",
        "directory_enumeration",
        "ip_information",
        "system_monitor",
        "target_manager",
        "view_logs",
        "settings",
    ]

    with (
        menu_harness(
            tmp_path, inputs=["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]
        ),
        patch.multiple(
            "voidscan.menu", **{name: MagicMock() for name in names}
        ),
    ):
        menu.run_menu()
