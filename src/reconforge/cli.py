import asyncio
import ipaddress
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
    get_session,
    scan_ports,
)
from reconforge.modules.subdomain_enum import (
    DEFAULT_CONCURRENCY,
    DEFAULT_NAMESERVERS,
    DEFAULT_RDTYPES,
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT,
    DnsStatus,
    SubdomainResult,
    build_names,
    create_resolver,
    enumerate_subdomains,
    load_labels,
    make_dns_probe,
)
from reconforge.report.console import (
    create_progress,
    print_banner,
    print_results,
    print_scan_config,
    print_summary,
    service_name,
)
from reconforge.report.enum_console import (
    print_enum_banner,
    print_enum_config,
    print_enum_results,
    print_enum_summary,
    print_found,
)

console = Console()

app = typer.Typer(help="Reconforge - reconaissance CLI")
console = Console()
err_console = Console(stderr=True)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


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
        session_factory = get_session(type)

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

            async def run_scan() -> list[PortResult]:
                async with session_factory() as probe:
                    return await scan_ports(
                        probe,
                        config.target,
                        ports_to_scan,
                        concurrency=concurrency,
                        timeout=timeout,
                        on_result=on_result,
                    )

            results = asyncio.run(run_scan())
    except KeyboardInterrupt:
        err_console.print("[yellow]Scan interrupted.[/yellow]")
        raise typer.Exit(code=130) from None
    duration = time.perf_counter() - start

    console.print()
    print_results(console, config.target, results)
    print_summary(console, results, duration, config.verbose, concurrency, timeout)


@app.command()
def enum(
    target: str = typer.Argument(..., help="Target domain, ex: example.com"),
    mode: EnumType = typer.Option(
        EnumType.SUBDOMAIN, "--mode", "-m", help="subdomain | directories"
    ),
    wordlist: Path = typer.Option(..., "--wordlist", "-w", exists=True, help="Path to wordlist"),
    concurrency: int = typer.Option(
        DEFAULT_CONCURRENCY, "--concurrency", "-c", min=1, help="Max simultaneous queries"
    ),
    timeout: float = typer.Option(
        DEFAULT_TIMEOUT, "--timeout", min=0.1, help="Per-query timeout in seconds"
    ),
    retries: int = typer.Option(
        DEFAULT_RETRIES, "--retries", min=1, help="Attempts per name on timeout"
    ),
    nameservers: list[str] | None = typer.Option(
        None, "--nameserver", "-n", help="DNS resolver IP (repeatable)"
    ),
    rdtypes: list[str] | None = typer.Option(
        None, "--record-type", "-r", help="DNS record type (repeatable), default: A"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose Output"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:

    try:
        config = ScanConfig.enum(
            target=target,
            mode=mode.value,
            wordlist=wordlist,
            verbose=verbose,
            output=output,
        )
    except ReconForgeValidationError as error:
        err_console.print(f"[bold red]Error:[/bold red] {error}")
        raise typer.Exit(code=1) from error

    if mode is not EnumType.SUBDOMAIN:
        err_console.print(f"[bold red]Error:[/bold red] mode {mode.value!r} is not implemented yet")
        raise typer.Exit(code=1)

    if _is_ip(config.target) or config.wordlist is None:
        err_console.print(
            "[bold red]Error:[/bold red] subdomain enumeration needs a domain name and a wordlist"
        )
        raise typer.Exit(code=1)

    domain = config.target.strip().lower().rstrip(".")
    names = build_names(load_labels(config.wordlist), domain)
    if not names:
        err_console.print("[bold red]Error:[/bold red] wordlist contains no valid DNS labels")
        raise typer.Exit(code=1)

    resolvers = nameservers or list(DEFAULT_NAMESERVERS)
    record_types = list(dict.fromkeys(t.upper() for t in (rdtypes or DEFAULT_RDTYPES)))

    probe = make_dns_probe(
        create_resolver(resolvers, timeout=timeout, lifetime=timeout * 2),
        record_types,
        retries,
    )

    print_enum_banner(console, domain, mode)
    if config.verbose:
        print_enum_config(
            console,
            domain,
            config.wordlist,
            len(names),
            resolvers,
            record_types,
            concurrency,
            timeout,
            retries,
        )

    start = time.perf_counter()

    try:
        with create_progress(console) as progress:
            task_id = progress.add_task(f"Enumerating {domain}", total=len(names))

            def on_result(result: SubdomainResult) -> None:
                progress.advance(task_id)
                if config.verbose and result.status == DnsStatus.FOUND:
                    print_found(progress.console, result)

            results = asyncio.run(
                enumerate_subdomains(probe, names, concurrency=concurrency, on_result=on_result)
            )
    except KeyboardInterrupt:
        err_console.print("[yellow]Enumeration interrupted.[/yellow]")
        raise typer.Exit(code=130) from None
    duration = time.perf_counter() - start

    console.print()
    print_enum_results(console, domain, results)
    print_enum_summary(console, results, duration, config.verbose, concurrency, timeout)


if __name__ == "__main__":
    app()
