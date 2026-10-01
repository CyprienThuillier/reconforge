import asyncio
import time
from pathlib import Path

import typer
from rich.console import Console

from reconforge.core.config import ScanConfig
from reconforge.core.enums import EnumType, ScanType
from reconforge.core.exceptions import ReconForgeValidationError
from reconforge.modules.cve import (
    CVE_SCANNERS,
    DEFAULT_CONCURRENCY,
    DEFAULT_REQUEST_TIMEOUT,
    CveResult,
    available_cves,
    resolve_scanners,
    scan_cves,
)
from reconforge.modules.port_scanning import (
    DEFAULT_CONNECT_TIMEOUT,
    PortResult,
    PortState,
    scan_ports_connect,
)
from reconforge.report.console import (
    create_progress,
    cve_result_line,
    print_banner,
    print_cve_catalog,
    print_cve_config,
    print_cve_results,
    print_cve_summary,
    print_results,
    print_scan_config,
    print_summary,
    service_name,
)

console = Console()

app = typer.Typer(help="Reconforge - reconaissance CLI")
err_console = Console(stderr=True)

CVE_HELP = f"CVE scanner id, repeatable. Available: {', '.join(available_cves())}. Default: all"


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
    except ReconForgeValidationError as error:
        err_console.print(f"[bold red]Error:[/bold red] {error}")
        raise typer.Exit(code=1) from error

    ports_to_scan = config.ports
    if ports_to_scan is None:
        err_console.print("[bold red]Error:[/bold red] no ports to scan")
        raise typer.Exit(code=1)

    print_banner(console, config.target)
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
                scan_ports_connect(
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


@app.command()
def cve(
    target: str | None = typer.Argument(None, help="Target URL, ex: https://example.com"),
    cves: list[str] = typer.Option([], "--cve", "-C", help=CVE_HELP),
    paths: list[str] = typer.Option(
        [],
        "--path",
        "-P",
        help="Absolute URL path to probe, repeatable. Default: /",
    ),
    concurrency: int = typer.Option(
        DEFAULT_CONCURRENCY, "--concurrency", "-c", help="Max simultaneous probes"
    ),
    timeout: float = typer.Option(
        DEFAULT_REQUEST_TIMEOUT, "--timeout", min=0.1, help="Per-request timeout in seconds"
    ),
    insecure: bool = typer.Option(
        True, "--insecure", "-k", help="Disable TLS certificate verification (default)"
    ),
    list_cves: bool = typer.Option(
        False, "--list", "-l", help="List the CVE scanners available and exit"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose Output"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:

    if list_cves:
        print_cve_catalog(console, CVE_SCANNERS)
        return

    if not target:
        err_console.print("[bold red]Error:[/bold red] a target URL is required")
        raise typer.Exit(code=1)

    try:
        config = ScanConfig.cve_scan(
            target=target,
            cves=cves,
            paths=paths,
            output=output,
            verbose=verbose,
        )
        scanners = resolve_scanners(config.cves)
    except ReconForgeValidationError as error:
        err_console.print(f"[bold red]Error:[/bold red] {error}")
        raise typer.Exit(code=1) from error

    paths_to_probe = config.paths or ["/"]
    probe_count = len(scanners) * len(paths_to_probe)

    print_banner(console, config.target, "CVE detection")
    if config.verbose:
        print_cve_config(
            console,
            config.target,
            [scanner.info.id for scanner in scanners],
            paths_to_probe,
            concurrency,
            timeout,
            not insecure,
        )

    start = time.perf_counter()

    try:
        with create_progress(console) as progress:
            task_id = progress.add_task(f"Scanning {config.target}", total=probe_count)

            def on_result(result: CveResult) -> None:
                progress.advance(task_id)
                if config.verbose:
                    progress.console.print(cve_result_line(result))

            results = asyncio.run(
                scan_cves(
                    config.target,
                    scanners,
                    paths=paths_to_probe,
                    concurrency=concurrency,
                    timeout=timeout,
                    verify_ssl=not insecure,
                    on_result=on_result,
                )
            )
    except KeyboardInterrupt:
        err_console.print("[yellow]Scan interrupted.[/yellow]")
        raise typer.Exit(code=130) from None
    duration = time.perf_counter() - start

    console.print()
    print_cve_results(console, config.target, results)
    print_cve_summary(console, results, duration, config.verbose, concurrency, timeout)


if __name__ == "__main__":
    app()
