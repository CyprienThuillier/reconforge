"""Rich-based console rendering for scan output."""

import socket
from collections.abc import Sequence

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from reconforge.core.enums import ScanType
from reconforge.modules.port_scanning import PortResult, PortState


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def print_banner(console: Console, target: str, scan_type: ScanType) -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]ReconForge[/bold cyan] · {scan_type.value} scan\n"
            f"Target: [bold]{target}[/bold]",
            border_style="cyan",
        )
    )


def print_scan_config(
    console: Console,
    target: str,
    port_count: int,
    concurrency: int,
    timeout: float,
) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Target", target)
    grid.add_row("Ports", str(port_count))
    grid.add_row("Concurrency", str(concurrency))
    grid.add_row("Timeout", f"{timeout}s")
    console.print(Panel(grid, title="Scan configuration", border_style="dim", expand=False))


def create_progress(console: Console) -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def build_results_table(target: str, results: Sequence[PortResult]) -> Table:
    table = Table(title=f"Open ports on {target}", box=box.ROUNDED, header_style="bold")
    table.add_column("Port", justify="right", style="cyan")
    table.add_column("Proto")
    table.add_column("State")
    table.add_column("Service")

    for result in results:
        if result.state == PortState.OPEN:
            table.add_row(
                str(result.port),
                "tcp",
                "[bold green]open[/bold green]",
                service_name(result.port),
            )
    return table


def print_results(console: Console, target: str, results: Sequence[PortResult]) -> None:
    open_count = sum(1 for result in results if result.state == PortState.OPEN)

    if open_count == 0:
        console.print("[yellow]No open ports found.[/yellow]")
        return

    console.print(build_results_table(target, results))


def print_summary(
    console: Console,
    results: Sequence[PortResult],
    duration: float,
    verbose: bool,
    concurrency: int,
    timeout: float,
) -> None:
    total = len(results)
    open_count = sum(1 for result in results if result.state == PortState.OPEN)
    closed_count = total - open_count

    console.print(
        f"[bold]Scan complete[/bold] — [green]{open_count} open[/green], "
        f"{closed_count} closed/filtered · {total} ports in {duration:.2f}s"
    )

    if not verbose:
        return

    if duration > 0:
        rate = total / duration
    else:
        rate = 0.0

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Ports scanned", str(total))
    grid.add_row("Open", f"[green]{open_count}[/green]")
    grid.add_row("Closed/filtered", str(closed_count))
    grid.add_row("Duration", f"{duration:.2f}s")
    grid.add_row("Rate", f"{rate:.0f} ports/s")
    grid.add_row("Concurrency", str(concurrency))
    grid.add_row("Timeout", f"{timeout}s")
    console.print(Panel(grid, title="Statistics", border_style="dim", expand=False))
