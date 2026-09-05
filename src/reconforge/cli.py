from pathlib import Path

import typer

from reconforge.core.config import ScanConfig
from reconforge.core.enums import EnumType, ScanType

app = typer.Typer(help="Reconforge - reconaissance CLI")


@app.command()
def pscan(
    target: str = typer.Argument(..., help="Target host or IP"),
    ports: str = typer.Option("1-1000", "--ports", "-p", help="Port range, ex: 1-10000 or 80,443"),
    type: ScanType = typer.Option(ScanType.TCP, "--type", "-t", help="Scan technique"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose Output"),
    output: Path | None = typer.Option(None, "--output", "-o", help=" Output file path"),
) -> None:

    config = ScanConfig(
        target=target,
        ports=ports,
        scan_type=type.value,
        output=output,
        verbose=verbose,
    )

    #typer.echo(config)


@app.command()
def enum(
    target: str = typer.Argument(..., help="Target host or IM"),
    mode: EnumType = typer.Option(EnumType.SUBDOMAIN, "--mode", "-m", help="subdomains | folders"),
    wordlist: Path = typer.Option(..., "--wordlist", "-w", exists=True, help="Path to wordlist"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose Output"),
    output: Path | None = typer.Option(None, "--output", "-o", help=" Output file path"),
) -> None:

    config = ScanConfig(
        target=target,
        mode=mode.value,
        wordlist=wordlist,
        verbose=verbose,
        output=output,
    )

    typer.echo(config)


if __name__ == "__main__":
    app()
