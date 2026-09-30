from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from reconforge.core.validators import (
    normalize_url,
    validate_output,
    validate_path,
    validate_port,
    validate_target,
    validate_url,
    validate_wordlist,
)

DEFAULT_PROBE_PATHS = ("/",)


class ScanConfig:
    def __init__(
        self,
        target: str,
        ports: list[int] | None = None,
        scan_type: str | None = None,
        mode: str | None = None,
        wordlist: Path | None = None,
        cves: list[str] | None = None,
        paths: list[str] | None = None,
        verbose: bool = False,
        output: Path | None = None,
    ):
        self.target = target
        self.ports = ports
        self.scan_type = scan_type
        self.mode = mode
        self.wordlist = wordlist
        self.cves = cves
        self.paths = paths
        self.output = output
        self.verbose = verbose

    @classmethod
    def port_scan(
        cls,
        target: str,
        ports: str | None = None,
        scan_type: str | None = None,
        mode: str | None = None,
        wordlist: Path | None = None,
        verbose: bool = False,
        output: Path | None = None,
    ) -> "ScanConfig":

        validate_target(target)

        parsed_ports: list[int] | None = None
        if ports is not None:
            validate_port(ports)
            parsed_ports = parse_ports(ports)

        output_path: Path | None = None
        if output is not None:
            validate_output(output)
            output_path = create_output_path(output)

        return cls(
            target=target,
            ports=parsed_ports,
            scan_type=scan_type,
            verbose=verbose,
            output=output_path,
        )

    @classmethod
    def enum(
        cls,
        target: str,
        ports: str | None = None,
        scan_type: str | None = None,
        mode: str | None = None,
        wordlist: Path | None = None,
        verbose: bool = False,
        output: Path | None = None,
    ) -> "ScanConfig":

        validate_target(target)

        wordlist_path: Path | None = None
        if wordlist is not None:
            validate_wordlist(wordlist)
            wordlist_path = wordlist

        output_path: Path | None = None
        if output is not None:
            validate_output(output)
            output_path = create_output_path(output)

        return cls(
            target=target,
            mode=mode,
            wordlist=wordlist_path,
            verbose=verbose,
            output=output_path,
        )

    @classmethod
    def cve_scan(
        cls,
        target: str,
        cves: Sequence[str] | None = None,
        paths: str | Sequence[str] | None = None,
        verbose: bool = False,
        output: Path | None = None,
    ) -> "ScanConfig":
        validate_url(target)

        output_path: Path | None = None
        if output is not None:
            validate_output(output)
            output_path = create_output_path(output)

        normalized_target = normalize_url(target)

        return cls(
            target=normalized_target,
            cves=list(cves or []),
            paths=parse_paths(paths, normalized_target),
            verbose=verbose,
            output=output_path,
        )


def parse_ports(ports: str) -> list[int]:
    if "-" in ports:
        start_str, end_str = ports.split("-")
        return list(range(int(start_str), int(end_str) + 1))
    if "," in ports:
        return [int(port) for port in ports.split(",")]
    return [int(ports)]


def default_path_for(target: str) -> str:
    path = urlsplit(target).path
    return "" if path not in ("", "/") else "/"


def parse_paths(paths: str | Sequence[str] | None, target: str | None = None) -> list[str]:
    candidates: Sequence[str] = (
        () if paths is None else (paths.split(",") if isinstance(paths, str) else list(paths))
    )

    parsed: list[str] = []
    for candidate in candidates:
        path = candidate.strip()
        if not path:
            continue
        normalized = path if path.startswith("/") else f"/{path}"
        validate_path(normalized)
        parsed.append(normalized)

    if parsed:
        return parsed
    return [default_path_for(target)] if target is not None else list(DEFAULT_PROBE_PATHS)


def create_output_path(output: Path) -> Path:
    output_path = Path(output).expanduser().resolve()
    if output_path.is_dir():
        filename = f"report_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.log"
        return output_path / filename
    return output_path
