"""Rich-based console rendering for subdomain enumeration output."""

from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path

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

from reconforge.core.enums import EnumType
from reconforge.modules.subdomain_enum import DnsStatus, SubdomainResult


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


def format_records(records: Mapping[str, Sequence[str]]) -> str:
    return "  ".join(f"{rdtype}: {', '.join(values)}" for rdtype, values in records.items())


def print_enum_banner(console: Console, target: str, mode: EnumType) -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]ReconForge[/bold cyan] · {mode.value} enumeration\n"
            f"Target: [bold]{target}[/bold]",
            border_style="cyan",
        )
    )


def print_enum_config(
    console: Console,
    target: str,
    wordlist: Path,
    name_count: int,
    nameservers: Sequence[str],
    rdtypes: Sequence[str],
    concurrency: int,
    timeout: float,
    retries: int,
) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Target", target)
    grid.add_row("Wordlist", str(wordlist))
    grid.add_row("Names", str(name_count))
    grid.add_row("Nameservers", ", ".join(nameservers))
    grid.add_row("Record types", ", ".join(rdtypes))
    grid.add_row("Concurrency", str(concurrency))
    grid.add_row("Timeout", f"{timeout}s")
    grid.add_row("Retries", str(retries))
    console.print(Panel(grid, title="Enumeration configuration", border_style="dim", expand=False))


def print_found(console: Console, result: SubdomainResult) -> None:
    """One-line live output for a discovered subdomain (verbose mode)."""
    console.print(
        f"[green][+][/green] {escape(result.name)}  {escape(format_records(result.records))}"
    )


def build_enum_table(target: str, results: Sequence[SubdomainResult]) -> Table:
    table = Table(title=f"Subdomains found for {target}", box=box.ROUNDED, header_style="bold")
    table.add_column("Subdomain", style="cyan")
    table.add_column("Type")
    table.add_column("Records")

    for result in results:
        if result.status != DnsStatus.FOUND:
            continue
        for index, (rdtype, values) in enumerate(result.records.items()):
            table.add_row(
                f"[bold]{escape(result.name)}[/bold]" if index == 0 else "",
                rdtype,
                escape("\n".join(values)),
            )
    return table


def print_enum_results(console: Console, target: str, results: Sequence[SubdomainResult]) -> None:
    if not any(result.status == DnsStatus.FOUND for result in results):
        console.print("[yellow]No subdomains found.[/yellow]")
        return

    console.print(build_enum_table(target, results))


def print_enum_summary(
    console: Console,
    results: Sequence[SubdomainResult],
    duration: float,
    verbose: bool,
    concurrency: int,
    timeout: float,
) -> None:
    total = len(results)
    counts = Counter(result.status for result in results)
    found = counts[DnsStatus.FOUND]

    console.print(
        f"[bold]Enumeration complete[/bold] — [green]{found} found[/green], "
        f"{total - found} unresolved · {total} names in {duration:.2f}s"
    )

    if not verbose:
        return

    rate = total / duration if duration > 0 else 0.0

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column()
    grid.add_row("Names tested", str(total))
    grid.add_row("Found", f"[green]{found}[/green]")
    grid.add_row("Not found (NXDOMAIN)", str(counts[DnsStatus.NOT_FOUND]))
    grid.add_row("No data", str(counts[DnsStatus.NO_DATA]))
    grid.add_row("Failed (timeouts)", str(counts[DnsStatus.FAILED]))
    grid.add_row("Errors", str(counts[DnsStatus.ERROR]))
    grid.add_row("Duration", f"{duration:.2f}s")
    grid.add_row("Rate", f"{rate:.0f} names/s")
    grid.add_row("Concurrency", str(concurrency))
    grid.add_row("Timeout", f"{timeout}s")
    console.print(Panel(grid, title="Statistics", border_style="dim", expand=False))