import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from reconforge.core.config import ScanConfig
from reconforge.core.enums import EnumType, ScanType
from reconforge.core.exceptions import *
from reconforge.modules.port_scanning import PortState, scan_ports_connect

console = Console()

app = typer.Typer(help="Reconforge - reconaissance CLI")


@app.command()
def pscan(
    target: str = typer.Argument(..., help="Target host or IP"),
    ports: str = typer.Option("1-1000", "--ports", "-p", help="Port range, ex: 1-10000 or 80,443"),
    type: ScanType = typer.Option(ScanType.TCP, "--type", "-t", help="Scan technique"),
    concurrency: int = typer.Option(
        500, "--concurrency", "-c", help="Max simultaneous connections"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose Output"),
    output: Path | None = typer.Option(None, "--output", "-o", help=" Output file path"),
) -> None:

    config = ScanConfig.port_scan(
        target=target,
        ports=ports,
        scan_type=type.value,
        output=output,
        verbose=verbose,
    )

    if config.ports is None:
        raise InvalidPortRangeError("Parsed port list is empty")

    results = asyncio.run(scan_ports_connect(config.target, config.ports, concurrency=concurrency))

    table = Table(title=f"ReconForge — {config.target}")
    table.add_column("Port", justify="right")
    table.add_column("State")

    for result in results:
        if result.state == PortState.OPEN:
            state_display = "[bold green]OPEN[/bold green]"
        else:
            state_display = "[dim]closed[/dim]"
        table.add_row(str(result.port), state_display)

    console.print(table)


@app.command()
def enum(
    target: str = typer.Argument(..., help="Target host or IP"),
    mode: EnumType = typer.Option(
        EnumType.SUBDOMAIN, "--mode", "-m", help="subdomains | directories"
    ),
    wordlist: Path = typer.Option(..., "--wordlist", "-w", exists=True, help="Path to wordlist"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose Output"),
    output: Path | None = typer.Option(None, "--output", "-o", help=" Output file path"),
) -> None:

    config = ScanConfig.enum(
        target=target,
        mode=mode.value,
        wordlist=wordlist,
        verbose=verbose,
        output=output,
    )

    typer.echo(config)


if __name__ == "__main__":
    app()
