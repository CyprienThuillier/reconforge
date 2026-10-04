import io
import socket

import pytest
from rich.console import Console

from reconforge.core.enums import ScanType
from reconforge.modules.port_scanning import PortResult, PortState
from reconforge.report.console import (
    build_results_table,
    print_banner,
    print_summary,
    service_name,
)


def _results() -> list[PortResult]:
    return [
        PortResult(port=22, state=PortState.OPEN),
        PortResult(port=23, state=PortState.CLOSED),
        PortResult(port=80, state=PortState.OPEN),
    ]


def test_service_name_returns_known_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getservbyport", lambda port, proto: "ssh")

    assert service_name(22) == "ssh"


def test_service_name_falls_back_to_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(port: int, proto: str) -> str:
        raise OSError("not found")

    monkeypatch.setattr(socket, "getservbyport", _raise)

    assert service_name(65000) == "unknown"


def test_build_results_table_keeps_only_open_ports() -> None:
    table = build_results_table("example.com", _results())

    assert table.row_count == 2


def test_print_summary_reports_counts() -> None:
    buffer = io.StringIO()
    console = Console(file=buffer, width=120)

    print_summary(console, _results(), duration=2.0, verbose=False, concurrency=500, timeout=1.0)

    output = buffer.getvalue()
    assert "2 open" in output
    assert "1 closed/filtered" in output
    assert "ports/s" not in output


def test_print_summary_verbose_adds_statistics() -> None:
    buffer = io.StringIO()
    console = Console(file=buffer, width=120)

    print_summary(console, _results(), duration=2.0, verbose=True, concurrency=500, timeout=1.0)

    assert "ports/s" in buffer.getvalue()


def test_print_banner_shows_target_and_scan_type() -> None:
    buffer = io.StringIO()
    console = Console(file=buffer, width=120)

    print_banner(console, "example.com", ScanType.CONNECT)

    output = buffer.getvalue()
    assert "example.com" in output
    assert "connect scan" in output
