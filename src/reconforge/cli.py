import asyncio
import time
from pathlib import Path

import typer
from rich.console import Console

from reconforge.core.config import ScanConfig
from reconforge.core.enums import EnumType, ScanType
from reconforge.core.exceptions import *
from reconforge.modules.port_scanning import (
    DEFAULT_CONNECT_TIMEOUT,
    PortResult,
    PortState,
    get_probe,
    scan_ports,
)
from reconforge.report.console import (
    create_progress,
    print_banner,
    print_results,
    print_scan_config,
    print_summary,
    service_name,
)

console = Console()

app = typer.Typer(help="Reconforge - reconaissance CLI")
console = Console()
err_console = Console(stderr=True)


@app.command()
def pscan(
    target: str = typer.Argument(..., help="Target host or IP"),
    ports: str = typer.Option("1-1000", "--ports", "-p", help="Port range, ex: 1-10000 or 80,443"),
    type: ScanType = typer.Option(ScanType.CONNECT, "--type", "-t", help="Scan technique"),
    concurrency: int = typer.Option(
        500, "--concurrency", "-c", help="Max simultaneous connections"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose Output"),
    output: Path | None = typer.Option(None, "--output", "-o", help=" Output file path"),
    timeout: float = typer.Option(
        DEFAULT_CONNECT_TIMEOUT, "--timeout", min=0.1, help="Per-port timeout in seconds"
    ),
) -> None:

    try:
        config = ScanConfig.port_scan(
            target=target,
            ports=ports,
            scan_type=type.value,
            output=output,
            verbose=verbose,
        )
        probe = get_probe(type)

    except ReconForgeValidationError as error:
        err_console.print(f"[bold red]Error:[/bold red] {error}")
        raise typer.Exit(code=1) from error

    ports_to_scan = config.ports
    if ports_to_scan is None:
        err_console.print("[bold red]Error:[/bold red] no ports to scan")
        raise typer.Exit(code=1)

    print_banner(console, config.target, type)
    if config.verbose:
        print_scan_config(console, config.target, len(ports_to_scan), concurrency, timeout)

    start = time.perf_counter()

    try:
        with create_progress(console) as progress:
            task_id = progress.add_task(f"Scanning {config.target}", total=len(ports_to_scan))

            def on_result(result: PortResult) -> None:
                progress.advance(task_id)
                if config.verbose and result.state == PortState.OPEN:
                    progress.console.print(
                        f"[green][+][/green] {result.port}/tcp open  {service_name(result.port)}"
                    )

            results = asyncio.run(
                scan_ports(
                    probe,
                    config.target,
                    ports_to_scan,
                    concurrency=concurrency,
                    timeout=timeout,
                    on_result=on_result,
                )
            )
    except KeyboardInterrupt:
        err_console.print("[yellow]Scan interrupted.[/yellow]")
        raise typer.Exit(code=130) from None
    duration = time.perf_counter() - start

    console.print()
    print_results(console, config.target, results)
    print_summary(console, results, duration, config.verbose, concurrency, timeout)


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
