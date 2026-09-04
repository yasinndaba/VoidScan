"""Interactive menu system for VoidScan."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm, Prompt

from voidscan.config import Config
from voidscan.targets import TargetManager
from voidscan.scanners.nmap import run_nmap


console = Console()


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
            "\n[bold yellow]Authorized Reconnaissance & Security Assessment Toolkit[/bold yellow]"
            "\n[dim]Written by Voidara[/dim]",
            border_style="cyan",
            expand=False,
        )
    )


def show_main_menu() -> str:
    """Display the main menu and return the user's selection."""

    table = Table(
        title="VoidScan v0.1.0",
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

    config = Config()
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
                    "Enter a valid IP address or domain."
                )

            console.input("\nPress Enter to continue...")

        elif choice == "2":
            targets = manager.list_targets()

            if not targets:
                console.print(
                    "\n[yellow]No targets have been saved.[/yellow]"
                )
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
                console.print(
                    f"\n[yellow]Target not found:[/yellow] {target}"
                )

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

    config = Config()
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

    show_banner()

    console.print(
        Panel(
            f"[bold cyan]Target:[/bold cyan] {target}\n"
            f"[bold cyan]Profile:[/bold cyan] {profile.title()}\n\n"
            "[yellow]Starting Nmap scan...[/yellow]",
            title="Network Scan",
            border_style="cyan",
        )
    )

    try:
        result = run_nmap(target, profile)

        console.print()

        if result.success:
            console.print(
                Panel(
                    result.output,
                    title="Nmap Results",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    result.output,
                    title=f"Nmap Failed — Exit Code {result.return_code}",
                    border_style="red",
                )
            )

    except (RuntimeError, ValueError) as exc:
        console.print(
            Panel(
                f"[bold red]{exc}[/bold red]",
                title="Scan Error",
                border_style="red",
            )
        )

    console.input("\nPress Enter to return to the menu...")

def placeholder(module_name: str) -> None:
    """Display a placeholder for an unimplemented module."""

    console.print(
        Panel(
            f"[bold]{module_name}[/bold]\n\n"
            "[yellow]Module not implemented yet.[/yellow]\n\n"
            "The scanner engine will be connected in a later milestone.",
            title="VoidScan",
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
            placeholder("Live Host Discovery")

        elif choice == "3":
            placeholder("Subdomain Enumeration")

        elif choice == "4":
            placeholder("Directory Enumeration")

        elif choice == "5":
            placeholder("IP Information")

        elif choice == "6":
            placeholder("System Monitor")

        elif choice == "7":
            target_manager()

        elif choice == "8":
            placeholder("View Logs")

        elif choice == "9":
            placeholder("Settings")

        elif choice == "0":
            console.print("\n[bold green]Session ended. Goodbye.[/bold green]")
            break

        else:
            console.print(
                "\n[bold red]Invalid option.[/bold red] "
                "Please select a valid menu option."
            )
            console.input("\nPress Enter to continue...")
