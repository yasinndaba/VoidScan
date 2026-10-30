"""Interactive menu system for VoidScan."""

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from voidscan import __version__
from voidscan.authorization import is_authorized, mark_authorized
from voidscan.config import Config, get_config
from voidscan.dependencies import is_tool_installed
from voidscan.errors import ScanCancelled, ScanTimeout
from voidscan.execution import ScanContext, run_with_progress
from voidscan.findings_directories import analyze_directory_result
from voidscan.findings_discovery import analyze_discovery_result
from voidscan.findings_ip_info import analyze_ip_info_result
from voidscan.findings_nmap import analyze_nmap_result
from voidscan.findings_subdomains import analyze_subdomain_result
from voidscan.html_reporter import save_html_report
from voidscan.reporter import (
    create_report,
    display_findings,
    display_report_summary,
    save_json_report,
)
from voidscan.scanners.directories import (
    DirectoryResult,
    enumerate_directories,
)
from voidscan.scanners.discovery import (
    discover_hosts,
    validate_discovery_scope,
)
from voidscan.scanners.ip_info import get_ip_info
from voidscan.scanners.nmap import run_nmap
from voidscan.scanners.subdomains import (
    SubdomainResult,
    enumerate_subdomains,
    merge_subdomain_results,
)
from voidscan.scanners.system_monitor import get_system_monitor
from voidscan.targets import TargetManager
from voidscan.validators import (
    is_valid_hostname,
    target_host,
    to_web_url,
)

console = Console()

# Result tables are capped so large scans stay readable. Full results are
# always available in the saved JSON and HTML reports.
MAX_RESULT_ROWS = 50


def print_result_cap(
    shown: int,
    total: int,
) -> None:
    """Explain that only part of a large result set is displayed."""

    if total <= shown:
        return

    console.print(
        f"\n[dim]Showing the first {shown} of {total} results. "
        "The full list is included in the saved report.[/dim]"
    )


def show_scan_cancelled(
    title: str = "Scan Cancelled",
) -> None:
    """Display the consistent panel shown after a cancelled scan."""

    console.print(
        Panel(
            "[yellow]The scan was cancelled. No results were saved.[/yellow]",
            title=title,
            border_style="yellow",
        )
    )


def show_scan_failure(
    title: str,
    exc: Exception,
) -> None:
    """Display a clear panel for invalid input, missing tools, or errors."""

    message = str(exc)
    panel_title = title
    border_style = "red"

    if isinstance(exc, ScanTimeout) or "timed out" in message.lower():
        panel_title = "Scan Timed Out"
        border_style = "yellow"
    elif "not installed" in message or "could not be found" in message:
        panel_title = "Missing Tool"
        border_style = "yellow"
    elif isinstance(exc, ValueError):
        panel_title = "Invalid Input"
        border_style = "red"

    console.print(
        Panel(
            f"[bold red]{message}[/bold red]"
            if border_style == "red"
            else f"[bold yellow]{message}[/bold yellow]",
            title=panel_title,
            border_style=border_style,
        )
    )


def _run_subdomain_scan(
    domain: str,
    engine: str,
    config: Config,
) -> SubdomainResult:
    """Run one subdomain engine with its configured timeout."""

    timeout = (
        config.amass_timeout if engine == "amass" else config.subfinder_timeout
    )

    return run_with_progress(
        f"Running {engine.title()}",
        lambda ctx: enumerate_subdomains(
            domain,
            engine,
            timeout=timeout,
            cancel_event=ctx.cancel_event,
        ),
        console=console,
    )


def require_authorization(target: str, config: Config) -> bool:
    """Confirm the user is authorized to test the target.

    The confirmation is remembered for the rest of the session, so only the
    first scan asks. ``--yes`` skips the prompt for scripted use.
    """

    if config.assume_yes or is_authorized():
        return True

    if not Confirm.ask(f"Confirm you are authorized to scan {target}?"):
        console.print(
            Panel(
                "[yellow]No scan was started. VoidScan is for authorized "
                "testing only.[/yellow]",
                title="Authorization Required",
                border_style="yellow",
            )
        )
        return False

    mark_authorized()

    return True


def show_banner() -> None:
    """Display the VoidScan banner."""
    console.clear()

    banner = r"""
██╗   ██╗ ██████╗ ██╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██║   ██║██╔═══██╗██║██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
╚██╗ ██╔╝██║   ██║██║██║  ██║███████╗██║     ███████║██╔██╗ ██║
 ╚████╔╝ ██║   ██║██║██║  ██║╚════██║██║     ██╔══██║██║╚██╗██║
  ╚██╔╝  ╚██████╔╝██║██████╔╝██████╔╝╚██████╗██║  ██║██║ ╚████║
   ╚═╝    ╚═════╝ ╚═╝╚═════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

    console.print(
        Panel(
            f"[bold cyan]{banner}[/bold cyan]"
            "\n[bold yellow]Authorized Reconnaissance & Security "
            "Assessment Toolkit[/bold yellow]"
            "\n[dim]Written by Voidara[/dim]",
            border_style="cyan",
            expand=False,
        )
    )


def show_main_menu() -> str:
    """Display the main menu and return the user's selection."""

    table = Table(
        title=f"VoidScan v{__version__}",
        show_header=False,
        border_style="cyan",
    )

    table.add_column("Option", style="bold cyan", width=8)
    table.add_column("Module")

    table.add_row("1", "Network Scan")
    table.add_row("2", "Live Host Discovery")
    table.add_row("3", "Subdomain Enumeration")
    table.add_row("4", "Directory Enumeration")
    table.add_row("5", "IP Information")
    table.add_row("6", "System Monitor")
    table.add_row("7", "Target Manager")
    table.add_row("8", "View Logs")
    table.add_row("9", "Settings")
    table.add_row("0", "Exit")

    console.print(table)

    return console.input("\n[bold cyan]Select an option:[/bold cyan] ").strip()


def target_manager() -> None:
    """Run the interactive target manager."""

    config = get_config()
    config.create_directories()

    manager = TargetManager(config.target_file)

    while True:
        show_banner()

        console.print(
            Panel(
                "[bold]Target Manager[/bold]\n\n"
                "Manage targets used by VoidScan.",
                border_style="cyan",
            )
        )

        table = Table(
            title="Target Manager",
            show_header=False,
            border_style="cyan",
        )

        table.add_column("Option", style="bold cyan", width=8)
        table.add_column("Action")

        table.add_row("1", "Add Target")
        table.add_row("2", "List Targets")
        table.add_row("3", "Remove Target")
        table.add_row("4", "Clear Targets")
        table.add_row("5", "Back")

        console.print(table)

        choice = Prompt.ask(
            "\n[bold cyan]Select an option[/bold cyan]",
            choices=["1", "2", "3", "4", "5"],
        )

        if choice == "1":
            target = Prompt.ask("[bold cyan]Enter target[/bold cyan]")

            try:
                added = manager.add_target(target)

                if added:
                    console.print(
                        f"\n[bold green]✓ Target added:[/bold green] {target}"
                    )
                else:
                    console.print(
                        f"\n[yellow]Target already exists:[/yellow] {target}"
                    )

            except ValueError:
                console.print(
                    "\n[bold red]✗ Invalid target.[/bold red] "
                    "Enter a valid IP address, domain, or URL."
                )

            console.input("\nPress Enter to continue...")

        elif choice == "2":
            targets = manager.list_targets()

            if not targets:
                console.print("\n[yellow]No targets have been saved.[/yellow]")
            else:
                target_table = Table(
                    title="Saved Targets",
                    border_style="green",
                )

                target_table.add_column("#", style="bold cyan")
                target_table.add_column("Target", style="white")

                for index, target in enumerate(targets, start=1):
                    target_table.add_row(str(index), target)

                console.print(target_table)

            console.input("\nPress Enter to continue...")

        elif choice == "3":
            targets = manager.list_targets()

            if not targets:
                console.print(
                    "\n[yellow]No targets available to remove.[/yellow]"
                )
                console.input("\nPress Enter to continue...")
                continue

            target = Prompt.ask(
                "[bold cyan]Enter target to remove[/bold cyan]"
            )

            if manager.remove_target(target):
                console.print(
                    f"\n[bold green]✓ Target removed:[/bold green] {target}"
                )
            else:
                console.print(f"\n[yellow]Target not found:[/yellow] {target}")

            console.input("\nPress Enter to continue...")

        elif choice == "4":
            targets = manager.list_targets()

            if not targets:
                console.print(
                    "\n[yellow]There are no targets to clear.[/yellow]"
                )
            elif Confirm.ask(
                "\n[bold red]Clear all saved targets?[/bold red]"
            ):
                manager.clear_targets()
                console.print(
                    "\n[bold green]✓ All targets cleared.[/bold green]"
                )

            console.input("\nPress Enter to continue...")

        elif choice == "5":
            break


def network_scan() -> None:
    """Run an interactive Nmap scan."""

    config = get_config()
    config.create_directories()

    manager = TargetManager(config.target_file)
    targets = manager.list_targets()

    show_banner()

    if not targets:
        console.print(
            Panel(
                "[bold yellow]No targets configured.[/bold yellow]\n\n"
                "Use Target Manager to add an IP address or domain "
                "before starting a scan.",
                title="Network Scan",
                border_style="yellow",
            )
        )

        console.input("\nPress Enter to return to the menu...")
        return

    target_table = Table(
        title="Select Target",
        show_header=False,
        border_style="cyan",
    )

    target_table.add_column("Option", style="bold cyan", width=8)
    target_table.add_column("Target")

    for index, target in enumerate(targets, start=1):
        target_table.add_row(str(index), target)

    console.print(target_table)

    choices = [str(index) for index in range(1, len(targets) + 1)]
    choices.append("0")

    target_choice = Prompt.ask(
        "\n[bold cyan]Select target (0 to cancel)[/bold cyan]",
        choices=choices,
    )

    if target_choice == "0":
        return

    target = targets[int(target_choice) - 1]
    scan_target = target_host(target)

    show_banner()

    profile_table = Table(
        title=f"Scan Profiles — {target}",
        show_header=False,
        border_style="cyan",
    )

    profile_table.add_column("Option", style="bold cyan", width=8)
    profile_table.add_column("Profile")
    profile_table.add_column("Description")

    profile_table.add_row(
        "1",
        "Quick Scan",
        "Fast scan of common ports",
    )

    profile_table.add_row(
        "2",
        "Standard Scan",
        "SYN scan with service detection",
    )

    profile_table.add_row(
        "3",
        "Full Scan",
        "Detailed assessment with OS/service detection",
    )

    profile_table.add_row(
        "0",
        "Back",
        "Return without scanning",
    )

    console.print(profile_table)

    profile_choice = Prompt.ask(
        "\n[bold cyan]Select scan profile[/bold cyan]",
        choices=["1", "2", "3", "0"],
    )

    profiles = {
        "1": "quick",
        "2": "standard",
        "3": "full",
    }

    if profile_choice == "0":
        return

    profile = profiles[profile_choice]

    if not require_authorization(scan_target, config):
        return

    show_banner()

    console.print(
        Panel(
            f"[bold cyan]Target:[/bold cyan] {scan_target}\n"
            f"[bold cyan]Profile:[/bold cyan] {profile.title()}\n\n"
            "[yellow]Starting Nmap scan...[/yellow]",
            title="Network Scan",
            border_style="cyan",
        )
    )
    try:
        result = run_with_progress(
            f"Running Nmap {profile} scan",
            lambda ctx: run_nmap(
                scan_target,
                profile,
                timeout=config.nmap_timeout,
                cancel_event=ctx.cancel_event,
            ),
            console=console,
        )

        console.print()

        if result.success:
            console.print(
                Panel(
                    result.output,
                    title="Nmap Results",
                    border_style="green",
                )
            )

            findings = analyze_nmap_result(result)
            display_findings(findings)

            if not findings:
                console.print(
                    Panel(
                        "[yellow]No open ports or services were "
                        "detected.[/yellow]",
                        title="No Results",
                        border_style="yellow",
                    )
                )

            save_json = Confirm.ask("Save scan results as JSON report?")
            save_html = Confirm.ask("Save scan results as HTML report?")

            if save_json or save_html:
                report = create_report(
                    scan_type="Network Scan",
                    target=scan_target,
                    result=result,
                    findings=findings,
                )

                if save_json:
                    try:
                        report_path = save_json_report(
                            report=report,
                            output_directory=config.report_dir,
                        )

                        console.print(
                            f"\n[green]Report saved:[/green] {report_path}"
                        )

                    except (OSError, TypeError) as exc:
                        console.print(
                            Panel(
                                f"[bold red]{exc}[/bold red]",
                                title="Report Error",
                                border_style="red",
                            )
                        )

                if save_html:
                    try:
                        html_path = save_html_report(
                            report=report,
                            output_directory=config.report_dir,
                        )

                        console.print(
                            f"\n[green]HTML report saved:[/green] {html_path}"
                        )

                    except (OSError, TypeError) as exc:
                        console.print(
                            Panel(
                                f"[bold red]{exc}[/bold red]",
                                title="HTML Report Error",
                                border_style="red",
                            )
                        )

                display_report_summary(report)

        else:
            console.print(
                Panel(
                    result.output,
                    title=f"Nmap Failed — Exit Code {result.return_code}",
                    border_style="red",
                )
            )

    except ScanCancelled:
        show_scan_cancelled("Network Scan")

    except (RuntimeError, ValueError) as exc:
        show_scan_failure("Scan Error", exc)

    console.input("\nPress Enter to return to the menu...")


def live_host_discovery() -> None:
    """Run an interactive live host discovery scan."""

    show_banner()

    config = get_config()
    config.create_directories()

    console.print(
        Panel(
            "[bold cyan]Live Host Discovery[/bold cyan]\n\n"
            "Discover hosts responding to ICMP ping within a network.\n"
            "[dim]Enter the network using CIDR notation.[/dim]",
            title="VoidScan",
            border_style="cyan",
        )
    )

    network = Prompt.ask(
        "\n[bold cyan]Network[/bold cyan]",
        default="192.168.1.0/24",
    ).strip()

    if not network:
        return

    try:
        total_hosts = validate_discovery_scope(network, config.max_hosts)
    except ValueError as exc:
        show_banner()
        console.print(
            Panel(
                f"[bold red]{exc}[/bold red]",
                title="Network Rejected",
                border_style="red",
            )
        )
        console.input("\nPress Enter to return to the menu...")
        return

    if not require_authorization(network, config):
        return

    show_banner()

    console.print(
        Panel(
            f"[bold cyan]Network:[/bold cyan] {network}\n"
            f"[bold cyan]Hosts:[/bold cyan] {total_hosts}\n\n"
            "[yellow]Starting host discovery...[/yellow]",
            title="Live Host Discovery",
            border_style="cyan",
        )
    )

    try:
        result = run_with_progress(
            "Discovering hosts",
            lambda ctx: discover_hosts(
                network,
                on_progress=ctx.update_progress,
                max_hosts=config.max_hosts,
                max_workers=config.discovery_workers,
                ping_timeout=config.ping_timeout,
                cancel_event=ctx.cancel_event,
            ),
            console=console,
        )

    except ScanCancelled:
        show_scan_cancelled("Live Host Discovery")
        console.input("\nPress Enter to return to the menu...")
        return

    except (RuntimeError, ValueError) as exc:
        show_scan_failure("Discovery Error", exc)
        console.input("\nPress Enter to return to the menu...")
        return

    console.print()

    if result.hosts:
        table = Table(
            title=f"Live Hosts — {result.network}",
            border_style="green",
        )

        table.add_column("#", style="bold cyan", width=6)
        table.add_column("Host", style="white")

        shown_hosts = result.hosts[:MAX_RESULT_ROWS]

        for index, host in enumerate(shown_hosts, start=1):
            table.add_row(str(index), host)

        console.print(table)
        print_result_cap(len(shown_hosts), len(result.hosts))
    else:
        console.print(
            Panel(
                "[yellow]No responding hosts were discovered.[/yellow]",
                title="Discovery Results",
                border_style="yellow",
            )
        )

    console.print(
        f"\n[bold cyan]Hosts scanned:[/bold cyan] {result.scanned}"
        f"\n[bold green]Hosts discovered:[/bold green] {result.reachable}"
    )

    findings = analyze_discovery_result(result)
    display_findings(findings)

    save_json = Confirm.ask("Save discovery results as JSON report?")
    save_html = Confirm.ask("Save discovery results as HTML report?")

    if save_json or save_html:
        report = create_report(
            scan_type="Live Host Discovery",
            target=result.network,
            result=result,
            findings=findings,
        )

        if save_json:
            try:
                report_path = save_json_report(
                    report=report,
                    output_directory=config.report_dir,
                )

                console.print(
                    f"\n[green]JSON report saved:[/green] {report_path}"
                )

            except (OSError, TypeError) as exc:
                console.print(
                    Panel(
                        f"[bold red]{exc}[/bold red]",
                        title="Report Error",
                        border_style="red",
                    )
                )

        if save_html:
            try:
                html_path = save_html_report(
                    report=report,
                    output_directory=config.report_dir,
                )

                console.print(
                    f"\n[green]HTML report saved:[/green] {html_path}"
                )

            except (OSError, TypeError) as exc:
                console.print(
                    Panel(
                        f"[bold red]{exc}[/bold red]",
                        title="HTML Report Error",
                        border_style="red",
                    )
                )

        display_report_summary(report)

    console.input("\nPress Enter to return to the menu...")


def subdomain_enumeration() -> None:
    """Run an interactive subdomain enumeration."""

    config = get_config()
    config.create_directories()

    manager = TargetManager(config.target_file)
    targets = manager.list_targets()

    show_banner()

    if not targets:
        console.print(
            Panel(
                "[bold yellow]No targets configured.[/bold yellow]\n\n"
                "Use Target Manager to add a domain before "
                "starting subdomain enumeration.",
                title="Subdomain Enumeration",
                border_style="yellow",
            )
        )

        console.input("\nPress Enter to return to the menu...")
        return

    target_table = Table(
        title="Select Domain",
        show_header=False,
        border_style="cyan",
    )

    target_table.add_column("Option", style="bold cyan", width=8)
    target_table.add_column("Target")

    for index, target in enumerate(targets, start=1):
        target_table.add_row(str(index), target)

    console.print(target_table)

    choices = [str(index) for index in range(1, len(targets) + 1)]
    choices.append("0")

    target_choice = Prompt.ask(
        "\n[bold cyan]Select domain (0 to cancel)[/bold cyan]",
        choices=choices,
    )

    if target_choice == "0":
        return

    domain = target_host(targets[int(target_choice) - 1])

    if not is_valid_hostname(domain):
        console.print(
            Panel(
                "[bold red]The selected target is not a valid domain."
                "[/bold red]\n\n"
                "Subdomain enumeration requires a domain such as "
                "example.com.",
                title="Invalid Target",
                border_style="red",
            )
        )

        console.input("\nPress Enter to return to the menu...")
        return

    show_banner()

    engine_table = Table(
        title=f"Enumeration Engine — {domain}",
        show_header=False,
        border_style="cyan",
    )

    engine_table.add_column("Option", style="bold cyan", width=8)
    engine_table.add_column("Engine")
    engine_table.add_column("Description")

    engine_table.add_row(
        "1",
        "Subfinder",
        "Fast passive subdomain discovery",
    )

    engine_table.add_row(
        "2",
        "Amass",
        "Passive subdomain discovery and reconnaissance",
    )

    engine_table.add_row(
        "0",
        "Back",
        "Return without scanning",
    )

    console.print(engine_table)

    engine_choice = Prompt.ask(
        "\n[bold cyan]Select enumeration engine[/bold cyan]",
        choices=["1", "2", "0"],
    )

    engines = {
        "1": "subfinder",
        "2": "amass",
    }

    if engine_choice == "0":
        return

    engine = engines[engine_choice]

    if not require_authorization(domain, config):
        return

    show_banner()

    engine_note = ""

    if engine == "amass":
        engine_note = (
            "\n[yellow]Amass passive enumeration can take several "
            "minutes. Press Ctrl+C to cancel the scan.[/yellow]"
        )

    console.print(
        Panel(
            f"[bold cyan]Domain:[/bold cyan] {domain}\n"
            f"[bold cyan]Engine:[/bold cyan] {engine.title()}\n\n"
            "[yellow]Starting subdomain enumeration...[/yellow]"
            f"{engine_note}",
            title="Subdomain Enumeration",
            border_style="cyan",
        )
    )

    try:
        result = _run_subdomain_scan(domain, engine, config)

    except ScanCancelled:
        show_scan_cancelled("Subdomain Enumeration")
        console.input("\nPress Enter to return to the menu...")
        return

    except (RuntimeError, ValueError) as exc:
        show_scan_failure("Enumeration Error", exc)
        console.input("\nPress Enter to return to the menu...")
        return

    console.print()

    if result.timed_out:
        partial_count = len(result.subdomains)
        partial_note = (
            f"{partial_count} partial subdomain(s) were collected."
            if partial_count
            else "No partial subdomains were collected."
        )

        console.print(
            Panel(
                f"[yellow]Amass did not finish within "
                f"{config.amass_timeout} seconds.[/yellow]\n\n"
                f"{partial_note}",
                title="Enumeration Timed Out",
                border_style="yellow",
            )
        )

        if engine == "amass" and Confirm.ask(
            "Retry with Subfinder for faster results?"
        ):
            try:
                retry = _run_subdomain_scan(
                    domain,
                    "subfinder",
                    config,
                )
            except ScanCancelled:
                show_scan_cancelled("Subdomain Enumeration")
                console.input("\nPress Enter to return to the menu...")
                return
            except (RuntimeError, ValueError) as exc:
                show_scan_failure("Enumeration Error", exc)
            else:
                result = merge_subdomain_results(result, retry)

                console.print(
                    Panel(
                        "[green]Subfinder results merged with the "
                        "partial Amass results.[/green]\n"
                        f"[bold cyan]Subdomains discovered:[/bold cyan] "
                        f"{len(result.subdomains)}",
                        title="Retry Complete",
                        border_style="green",
                    )
                )

        console.print()

    if result.subdomains:
        result_table = Table(
            title=f"Discovered Subdomains — {domain}",
            border_style="green",
        )

        result_table.add_column("#", style="bold cyan", width=6)
        result_table.add_column("Subdomain", style="white")

        shown_subdomains = result.subdomains[:MAX_RESULT_ROWS]

        for index, subdomain in enumerate(
            shown_subdomains,
            start=1,
        ):
            result_table.add_row(str(index), subdomain)

        console.print(result_table)
        print_result_cap(
            len(shown_subdomains),
            len(result.subdomains),
        )

        console.print(
            f"\n[bold green]Subdomains discovered:[/bold green] "
            f"{len(result.subdomains)}"
        )

    elif result.timed_out:
        console.print(
            Panel(
                "[yellow]The enumeration timed out before any "
                "subdomains were found.[/yellow]",
                title="Enumeration Results",
                border_style="yellow",
            )
        )

    elif result.success:
        console.print(
            Panel(
                "[yellow]No subdomains were discovered.[/yellow]",
                title="Enumeration Results",
                border_style="yellow",
            )
        )

    else:
        console.print(
            Panel(
                "The enumeration engine reported a failure.",
                title=f"Enumeration Failed — Exit Code {result.return_code}",
                border_style="red",
            )
        )

    can_report = result.success or bool(result.subdomains) or result.timed_out

    if can_report:
        findings = analyze_subdomain_result(result)
        display_findings(findings)

        save_json = Confirm.ask("Save enumeration results as JSON report?")
        save_html = Confirm.ask("Save enumeration results as HTML report?")

        if save_json or save_html:
            report = create_report(
                scan_type="Subdomain Enumeration",
                target=domain,
                result=result,
                findings=findings,
            )

            if save_json:
                try:
                    report_path = save_json_report(
                        report=report,
                        output_directory=config.report_dir,
                    )

                    console.print(
                        f"\n[green]JSON report saved:[/green] {report_path}"
                    )

                except (OSError, TypeError) as exc:
                    console.print(
                        Panel(
                            f"[bold red]{exc}[/bold red]",
                            title="Report Error",
                            border_style="red",
                        )
                    )

            if save_html:
                try:
                    html_path = save_html_report(
                        report=report,
                        output_directory=config.report_dir,
                    )

                    console.print(
                        f"\n[green]HTML report saved:[/green] {html_path}"
                    )

                except (OSError, TypeError) as exc:
                    console.print(
                        Panel(
                            f"[bold red]{exc}[/bold red]",
                            title="HTML Report Error",
                            border_style="red",
                        )
                    )

            display_report_summary(report)

    console.input("\nPress Enter to return to the menu...")


def directory_enumeration() -> None:
    """Run an interactive directory enumeration."""

    config = get_config()
    config.create_directories()

    manager = TargetManager(config.target_file)
    targets = manager.list_targets()

    show_banner()

    if not targets:
        console.print(
            Panel(
                "[bold yellow]No targets configured.[/bold yellow]\n\n"
                "Use Target Manager to add a target before "
                "starting directory enumeration.",
                title="Directory Enumeration",
                border_style="yellow",
            )
        )

        console.input("\nPress Enter to return to the menu...")
        return

    target_table = Table(
        title="Select Web Target",
        show_header=False,
        border_style="cyan",
    )

    target_table.add_column("Option", style="bold cyan", width=8)
    target_table.add_column("Target")

    for index, target in enumerate(targets, start=1):
        target_table.add_row(str(index), target)

    console.print(target_table)

    choices = [str(index) for index in range(1, len(targets) + 1)]
    choices.append("0")

    target_choice = Prompt.ask(
        "\n[bold cyan]Select target (0 to cancel)[/bold cyan]",
        choices=choices,
    )

    if target_choice == "0":
        return

    target = targets[int(target_choice) - 1]

    try:
        target = to_web_url(target)
    except ValueError:
        console.print(
            Panel(
                "[bold red]The selected target is not a valid web URL."
                "[/bold red]\n\n"
                "Directory enumeration requires a URL or host such as:\n"
                "https://example.com",
                title="Invalid Target",
                border_style="red",
            )
        )

        console.input("\nPress Enter to return to the menu...")
        return

    show_banner()

    engine_table = Table(
        title=f"Enumeration Engine — {target}",
        show_header=False,
        border_style="cyan",
    )

    engine_table.add_column("Option", style="bold cyan", width=8)
    engine_table.add_column("Engine")
    engine_table.add_column("Description")

    engine_table.add_row(
        "1",
        "FFUF",
        "Fast web fuzzing and directory discovery",
    )

    engine_table.add_row(
        "2",
        "DIRB",
        "Classic web content scanner",
    )

    engine_table.add_row(
        "0",
        "Back",
        "Return without scanning",
    )

    console.print(engine_table)

    engine_choice = Prompt.ask(
        "\n[bold cyan]Select enumeration engine[/bold cyan]",
        choices=["1", "2", "0"],
    )

    engines = {
        "1": "ffuf",
        "2": "dirb",
    }

    if engine_choice == "0":
        return

    engine = engines[engine_choice]

    show_banner()

    wordlist_choice = Prompt.ask(
        "\n[bold cyan]Wordlist[/bold cyan]\n"
        "1. Default common.txt\n"
        "2. Custom wordlist\n"
        "0. Cancel\n\n"
        "Select wordlist",
        choices=["1", "2", "0"],
    )

    if wordlist_choice == "0":
        return

    if wordlist_choice == "1":
        wordlist = None
    else:
        wordlist = Prompt.ask(
            "\n[bold cyan]Enter wordlist path[/bold cyan]"
        ).strip()

        if not wordlist:
            return

    if not require_authorization(target, config):
        return

    show_banner()

    selected_wordlist = "Default common.txt" if wordlist is None else wordlist

    console.print(
        Panel(
            f"[bold cyan]Target:[/bold cyan] {target}\n"
            f"[bold cyan]Engine:[/bold cyan] {engine.upper()}\n"
            f"[bold cyan]Wordlist:[/bold cyan] {selected_wordlist}\n\n"
            "[yellow]Starting directory enumeration...[/yellow]",
            title="Directory Enumeration",
            border_style="cyan",
        )
    )

    engine_timeout = (
        config.ffuf_timeout if engine == "ffuf" else config.dirb_timeout
    )

    def run_directory_enumeration(
        ctx: ScanContext,
    ) -> DirectoryResult:
        if wordlist is None:
            return enumerate_directories(
                target,
                engine,
                timeout=engine_timeout,
                cancel_event=ctx.cancel_event,
            )

        return enumerate_directories(
            target,
            engine,
            wordlist,
            timeout=engine_timeout,
            cancel_event=ctx.cancel_event,
        )

    try:
        result = run_with_progress(
            f"Running {engine.upper()}",
            run_directory_enumeration,
            console=console,
        )

    except ScanCancelled:
        show_scan_cancelled("Directory Enumeration")
        console.input("\nPress Enter to return to the menu...")
        return

    except (RuntimeError, ValueError) as exc:
        show_scan_failure("Enumeration Error", exc)
        console.input("\nPress Enter to return to the menu...")
        return

    console.print()

    if result.success and result.results:
        result_table = Table(
            title=f"Discovered Content — {target}",
            border_style="green",
        )

        result_table.add_column("#", style="bold cyan", width=6)
        result_table.add_column("Result", style="white")

        shown_results = result.results[:MAX_RESULT_ROWS]

        for index, item in enumerate(
            shown_results,
            start=1,
        ):
            result_table.add_row(str(index), item)

        console.print(result_table)
        print_result_cap(
            len(shown_results),
            len(result.results),
        )

        console.print(
            f"\n[bold green]Results discovered:[/bold green] "
            f"{len(result.results)}"
        )

    elif result.success:
        console.print(
            Panel(
                "[yellow]No directories or files were discovered.[/yellow]",
                title="Enumeration Results",
                border_style="yellow",
            )
        )

    else:
        console.print(
            Panel(
                "The enumeration engine reported a failure.",
                title=(f"Enumeration Failed — Exit Code {result.return_code}"),
                border_style="red",
            )
        )

    if result.success:
        findings = analyze_directory_result(result)
        display_findings(findings)

        save_json = Confirm.ask("Save enumeration results as JSON report?")
        save_html = Confirm.ask("Save enumeration results as HTML report?")

        if save_json or save_html:
            report = create_report(
                scan_type="Directory Enumeration",
                target=target,
                result=result,
                findings=findings,
            )

            if save_json:
                try:
                    report_path = save_json_report(
                        report=report,
                        output_directory=config.report_dir,
                    )

                    console.print(
                        f"\n[green]JSON report saved:[/green] {report_path}"
                    )

                except (OSError, TypeError) as exc:
                    console.print(
                        Panel(
                            f"[bold red]{exc}[/bold red]",
                            title="Report Error",
                            border_style="red",
                        )
                    )

            if save_html:
                try:
                    html_path = save_html_report(
                        report=report,
                        output_directory=config.report_dir,
                    )

                    console.print(
                        f"\n[green]HTML report saved:[/green] {html_path}"
                    )

                except (OSError, TypeError) as exc:
                    console.print(
                        Panel(
                            f"[bold red]{exc}[/bold red]",
                            title="HTML Report Error",
                            border_style="red",
                        )
                    )

            display_report_summary(report)

    console.input("\nPress Enter to return to the menu...")


def ip_information() -> None:
    """Display information about an IP address or hostname."""

    config = get_config()
    config.create_directories()

    manager = TargetManager(config.target_file)
    targets = manager.list_targets()

    show_banner()

    if not targets:
        console.print(
            Panel(
                "[bold yellow]No targets configured.[/bold yellow]\n\n"
                "Use Target Manager to add an IP address or domain "
                "before requesting IP information.",
                title="IP Information",
                border_style="yellow",
            )
        )

        console.input("\nPress Enter to return to the menu...")
        return

    target_table = Table(
        title="Select Target",
        show_header=False,
        border_style="cyan",
    )

    target_table.add_column("Option", style="bold cyan", width=8)
    target_table.add_column("Target")

    for index, target in enumerate(targets, start=1):
        target_table.add_row(str(index), target)

    console.print(target_table)

    choices = [str(index) for index in range(1, len(targets) + 1)]
    choices.append("0")

    target_choice = Prompt.ask(
        "\n[bold cyan]Select target (0 to cancel)[/bold cyan]",
        choices=choices,
    )

    if target_choice == "0":
        return

    target = target_host(targets[int(target_choice) - 1])

    if not require_authorization(target, config):
        return

    show_banner()

    console.print(
        Panel(
            f"[bold cyan]Target:[/bold cyan] {target}\n\n"
            "[yellow]Gathering IP information...[/yellow]",
            title="IP Information",
            border_style="cyan",
        )
    )

    try:
        with console.status(
            "[cyan]Resolving target...[/cyan]",
            spinner="dots",
        ):
            result = get_ip_info(target)

    except ValueError as exc:
        show_scan_failure("IP Information Error", exc)
        console.input("\nPress Enter to return to the menu...")
        return

    show_banner()

    info_table = Table(
        title=f"IP Information — {result.address}",
        border_style="green",
    )

    info_table.add_column("Property", style="bold cyan")
    info_table.add_column("Value", style="white")

    info_table.add_row("IP Address", result.address)
    info_table.add_row("Version", result.version)
    info_table.add_row(
        "Private",
        "Yes" if result.is_private else "No",
    )
    info_table.add_row(
        "Loopback",
        "Yes" if result.is_loopback else "No",
    )
    info_table.add_row(
        "Reserved",
        "Yes" if result.is_reserved else "No",
    )
    info_table.add_row(
        "Multicast",
        "Yes" if result.is_multicast else "No",
    )
    info_table.add_row(
        "Reverse DNS",
        result.reverse_dns or "Not available",
    )

    console.print(info_table)

    findings = analyze_ip_info_result(result)
    display_findings(findings)

    save_json = Confirm.ask("Save IP information as JSON report?")
    save_html = Confirm.ask("Save IP information as HTML report?")

    if save_json or save_html:
        report = create_report(
            scan_type="IP Information",
            target=target,
            result=result,
            findings=findings,
        )

        if save_json:
            try:
                report_path = save_json_report(
                    report=report,
                    output_directory=config.report_dir,
                )

                console.print(
                    f"\n[green]JSON report saved:[/green] {report_path}"
                )

            except (OSError, TypeError) as exc:
                console.print(
                    Panel(
                        f"[bold red]{exc}[/bold red]",
                        title="Report Error",
                        border_style="red",
                    )
                )

        if save_html:
            try:
                html_path = save_html_report(
                    report=report,
                    output_directory=config.report_dir,
                )

                console.print(
                    f"\n[green]HTML report saved:[/green] {html_path}"
                )

            except (OSError, TypeError) as exc:
                console.print(
                    Panel(
                        f"[bold red]{exc}[/bold red]",
                        title="HTML Report Error",
                        border_style="red",
                    )
                )

        display_report_summary(report)

    console.input("\nPress Enter to return to the menu...")


def system_monitor() -> None:
    """Display local system information."""
    console.print(
        Panel(
            "[bold cyan]System Monitor[/bold cyan]\nLocal system information",
            expand=False,
        )
    )

    try:
        result = get_system_monitor()
    except RuntimeError as exc:
        console.print(f"[red]System monitor failed:[/red] {exc}")
        return

    uptime = int(result.uptime_seconds)
    days, remainder = divmod(uptime, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)

    uptime_display = f"{days}d {hours}h {minutes}m"

    table = Table(title="System Information")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Hostname", result.hostname)
    table.add_row("Operating System", result.operating_system)
    table.add_row("Kernel", result.kernel)
    table.add_row("Architecture", result.architecture)
    table.add_row("CPU Cores", str(result.cpu_count))
    table.add_row("Memory Total", f"{result.memory_total_gb:.2f} GB")
    table.add_row("Memory Available", f"{result.memory_available_gb:.2f} GB")
    table.add_row("Disk Total", f"{result.disk_total_gb:.2f} GB")
    table.add_row("Disk Free", f"{result.disk_free_gb:.2f} GB")
    table.add_row("Uptime", uptime_display)

    console.print(table)

    console.input("\nPress Enter to return to the menu...")


def view_logs() -> None:
    """Display the most recent entries from the VoidScan log file."""

    show_banner()

    config = get_config()
    config.create_directories()

    log_file = config.log_dir / "voidscan.log"

    if not log_file.exists() or log_file.stat().st_size == 0:
        console.print(
            Panel(
                "[yellow]No log entries have been recorded yet.[/yellow]\n\n"
                f"[dim]Log file: {log_file}[/dim]",
                title="View Logs",
                border_style="yellow",
            )
        )

        console.input("\nPress Enter to return to the menu...")
        return

    lines = log_file.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines()
    preview = lines[-80:]

    console.print(
        Panel(
            Text("\n".join(preview)),
            title=(f"View Logs — last {len(preview)} of {len(lines)} entries"),
            border_style="cyan",
        )
    )

    console.input("\nPress Enter to return to the menu...")


def settings() -> None:
    """Display the current VoidScan configuration and tool status."""

    show_banner()

    config = get_config()
    config.create_directories()

    config_table = Table(
        title="VoidScan Settings",
        border_style="cyan",
    )

    config_table.add_column("Setting", style="bold cyan")
    config_table.add_column("Value")

    config_table.add_row("Version", __version__)
    config_table.add_row("Config file", str(config.config_file))
    config_table.add_row("Data directory", str(config.data_dir))
    config_table.add_row("Log directory", str(config.log_dir))
    config_table.add_row("Report directory", str(config.report_dir))
    config_table.add_row("Target file", str(config.target_file))
    config_table.add_row(
        "Timeouts (s)",
        (
            f"Nmap {config.nmap_timeout} · FFUF {config.ffuf_timeout} · "
            f"DIRB {config.dirb_timeout} · "
            f"Subfinder {config.subfinder_timeout} · "
            f"Amass {config.amass_timeout}"
        ),
    )
    config_table.add_row(
        "Discovery limits",
        (
            f"{config.max_hosts} hosts · "
            f"{config.discovery_workers} workers · "
            f"{config.ping_timeout}s ping timeout"
        ),
    )

    console.print(config_table)

    tools_table = Table(
        title="External Tools",
        border_style="cyan",
    )

    tools_table.add_column("Tool", style="bold cyan")
    tools_table.add_column("Status")

    for tool in ("nmap", "ffuf", "dirb", "subfinder", "amass"):
        installed = is_tool_installed(tool)
        status = (
            "[green]Installed[/green]" if installed else "[red]Missing[/red]"
        )

        tools_table.add_row(tool, status)

    console.print(tools_table)

    console.print(
        Panel(
            "[dim]Settings are read from the TOML file shown above. "
            "Environment variables and command-line flags can override "
            "them. Restart VoidScan after editing the file.[/dim]",
            border_style="yellow",
        )
    )

    console.input("\nPress Enter to return to the menu...")


def run_menu() -> None:
    """Run the interactive VoidScan menu."""

    while True:
        show_banner()

        choice = show_main_menu()

        if choice == "1":
            network_scan()

        elif choice == "2":
            live_host_discovery()

        elif choice == "3":
            subdomain_enumeration()

        elif choice == "4":
            directory_enumeration()

        elif choice == "5":
            ip_information()

        elif choice == "6":
            system_monitor()

        elif choice == "7":
            target_manager()

        elif choice == "8":
            view_logs()

        elif choice == "9":
            settings()

        elif choice == "0":
            console.print("\n[bold green]Session ended. Goodbye.[/bold green]")
            break

        else:
            console.print(
                "\n[bold red]Invalid option.[/bold red] "
                "Please select a valid menu option."
            )
            console.input("\nPress Enter to continue...")
