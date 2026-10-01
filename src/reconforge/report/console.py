"""Rich-based console rendering for scan output."""

import socket
from collections.abc import Sequence

from rich import box
from rich.console import Console
from rich.markup import escape
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

from reconforge.modules.cve import SEVERITY_RANK, CveResult, CveScanner, CveState, Severity
from reconforge.modules.port_scanning import PortResult, PortState


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def print_banner(console: Console, target: str, subtitle: str = "TCP connect scan") -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]ReconForge[/bold cyan] · {escape(subtitle)}\n"
            f"Target: [bold]{escape(target)}[/bold]",
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


# ------ CVE scan ------

CVE_STATE_STYLE: dict[CveState, str] = {
    CveState.VULNERABLE: "[bold red]VULNERABLE[/bold red]",
    CveState.NOT_VULNERABLE: "[green]not vulnerable[/green]",
    CveState.UNKNOWN: "[yellow]unknown[/yellow]",
}

CVE_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "[bold red]",
    Severity.HIGH: "[red]",
    Severity.MEDIUM: "[yellow]",
    Severity.LOW: "[cyan]",
    Severity.INFO: "[dim]",
}


def cve_result_line(result: CveResult) -> str:
    if result.state is CveState.VULNERABLE:
        marker = "[bold red][+][/bold red]"
    elif result.state is CveState.UNKNOWN:
        marker = "[yellow][?][/yellow]"
    else:
        marker = "[green][-][/green]"
    return f"{marker} {escape(result.cve.id)} {result.state.value}  {escape(result.url)}"


def print_cve_config(
    console: Console,
    target: str,
    cve_ids: Sequence[str],
    paths: Sequence[str],
    concurrency: int,
    timeout: float,
    verify_ssl: bool,
) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Target", escape(target))
    grid.add_row("CVEs", ", ".join(cve_ids) or "all")
    grid.add_row("Paths", ", ".join(paths) or "(target as given)")
    grid.add_row("Probes", str(len(cve_ids) * len(paths)))
    grid.add_row("Concurrency", str(concurrency))
    grid.add_row("Timeout", f"{timeout}s")
    grid.add_row("TLS verification", "on" if verify_ssl else "[yellow]off[/yellow]")
    console.print(Panel(grid, title="Scan configuration", border_style="dim", expand=False))


def build_cve_table(target: str, results: Sequence[CveResult]) -> Table:
    table = Table(title=f"CVE scan on {escape(target)}", box=box.ROUNDED, header_style="bold")
    table.add_column("CVE", style="cyan")
    table.add_column("Severity")
    table.add_column("CVSS", justify="right")
    table.add_column("Result")
    table.add_column("URL")

    for result in sorted(results, key=lambda item: SEVERITY_RANK[item.cve.severity]):
        table.add_row(
            escape(result.cve.id),
            f"{CVE_SEVERITY_STYLE[result.cve.severity]}{result.cve.severity.value.upper()}",
            f"{result.cve.cvss:.1f}",
            CVE_STATE_STYLE[result.state],
            escape(result.url),
        )
    return table


def build_finding_panel(result: CveResult) -> Panel:
    cve = result.cve

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Target", escape(result.url))
    grid.add_row("Severity", cve.severity.value.upper())
    grid.add_row("CVSS", f"{cve.cvss}")
    grid.add_row("CWE", cve.cwe)
    grid.add_row("Affected", cve.affected)
    grid.add_row("Evidence", escape(result.evidence))
    grid.add_row("Remediation", cve.remediation)
    for reference in cve.references:
        grid.add_row("Reference", reference)

    return Panel(
        grid,
        title=f"[bold red]{escape(cve.id)}[/bold red] — {escape(cve.name)}",
        border_style="red",
    )


def print_cve_results(console: Console, target: str, results: Sequence[CveResult]) -> None:
    if not results:
        console.print("[yellow]No CVE probe was run.[/yellow]")
        return

    console.print(build_cve_table(target, results))

    for result in results:
        if result.state is CveState.VULNERABLE:
            console.print(build_finding_panel(result))


def print_cve_summary(
    console: Console,
    results: Sequence[CveResult],
    duration: float,
    verbose: bool,
    concurrency: int,
    timeout: float,
) -> None:
    total = len(results)
    vulnerable = sum(1 for result in results if result.state is CveState.VULNERABLE)
    unknown = sum(1 for result in results if result.state is CveState.UNKNOWN)
    clean = total - vulnerable - unknown

    headline = (
        f"[bold red]{vulnerable} vulnerable[/bold red]"
        if vulnerable
        else "[green]0 vulnerable[/green]"
    )
    console.print(
        f"[bold]Scan complete[/bold] — {headline}, {clean} not vulnerable, "
        f"{unknown} unknown · {total} probes in {duration:.2f}s"
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
    grid.add_row("Probes", str(total))
    grid.add_row("Vulnerable", f"[red]{vulnerable}[/red]")
    grid.add_row("Not vulnerable", str(clean))
    grid.add_row("Unknown", f"[yellow]{unknown}[/yellow]")
    grid.add_row("Duration", f"{duration:.2f}s")
    grid.add_row("Rate", f"{rate:.1f} probes/s")
    grid.add_row("Concurrency", str(concurrency))
    grid.add_row("Timeout", f"{timeout}s")
    console.print(Panel(grid, title="Statistics", border_style="dim", expand=False))


def print_cve_catalog(console: Console, registry: dict[str, type[CveScanner]]) -> None:
    table = Table(title="CVE scanners", box=box.ROUNDED, header_style="bold")
    table.add_column("Id", style="cyan")
    table.add_column("CVE")
    table.add_column("Severity")
    table.add_column("CVSS", justify="right")
    table.add_column("Name")

    for key, scanner in sorted(registry.items()):
        info = scanner.info
        table.add_row(
            escape(key),
            escape(info.id),
            f"{CVE_SEVERITY_STYLE[info.severity]}{info.severity.value.upper()}",
            f"{info.cvss:.1f}",
            escape(info.name),
        )

    console.print(table)
    console.print("[dim]Select with --cve <id>, repeatable. Omit it to scan them all.[/dim]")
