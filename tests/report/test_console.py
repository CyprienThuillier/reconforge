import io
import socket

import pytest
from rich.console import Console

from reconforge.modules.cve import CveInfo, CveResult, CveState, Severity
from reconforge.modules.cve.react2shell import INFO as REACT2SHELL_INFO
from reconforge.modules.cve.react2shell import React2ShellScanner
from reconforge.modules.port_scanning import PortResult, PortState
from reconforge.report.console import (
    build_cve_table,
    build_results_table,
    cve_result_line,
    print_banner,
    print_cve_catalog,
    print_cve_config,
    print_cve_results,
    print_cve_summary,
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


# --- CVE rendering ----------------------------------------------------------


def _console() -> tuple[Console, io.StringIO]:
    buffer = io.StringIO()
    return Console(file=buffer, width=120), buffer


def _cve_results() -> list[CveResult]:
    info = CveInfo(
        id="CVE-2025-9999",
        name="Low issue",
        severity=Severity.LOW,
        cvss=3.1,
        cwe="CWE-200",
        affected="stub",
        remediation="upgrade",
        references=("https://example.com/advisory",),
    )
    return [
        CveResult(REACT2SHELL_INFO, CveState.VULNERABLE, "https://example.com/api", "digest"),
        CveResult(info, CveState.NOT_VULNERABLE, "https://example.com/", "HTTP 200"),
    ]


def test_print_banner_accepts_subtitle_and_escapes_target():
    console, buffer = _console()

    print_banner(console, "example.com", "CVE detection")
    output = buffer.getvalue()

    assert "CVE detection" in output
    assert "TCP connect scan" not in output


def test_build_cve_table_sorts_most_severe_first():
    console, buffer = _console()

    console.print(build_cve_table("example.com", _cve_results()))
    output = buffer.getvalue()

    assert output.index("CVE-2025-55182") < output.index("CVE-2025-9999")


def test_print_cve_results_shows_vulnerable_finding():
    console, buffer = _console()

    print_cve_results(console, "example.com", _cve_results())
    output = buffer.getvalue()

    assert "VULNERABLE" in output
    assert "Remediation" in output
    assert "react.dev" in output


def test_print_cve_results_reports_empty_run():
    console, buffer = _console()

    print_cve_results(console, "example.com", [])
    assert "No CVE probe" in buffer.getvalue()


def test_cve_result_line_marks_each_state():
    vulnerable, clean = _cve_results()

    assert "[+]" in cve_result_line(vulnerable)
    assert "[-]" in cve_result_line(clean)
    assert "[?]" in cve_result_line(
        CveResult(vulnerable.cve, CveState.UNKNOWN, "https://example.com/", "timeout")
    )


def test_print_cve_summary_reports_counts_and_verbose_stats():
    console, buffer = _console()

    print_cve_summary(console, _cve_results(), 2.0, verbose=False, concurrency=10, timeout=5.0)
    assert "1 vulnerable" in buffer.getvalue()

    console, buffer = _console()
    print_cve_summary(console, _cve_results(), 2.0, verbose=True, concurrency=10, timeout=5.0)
    assert "probes/s" in buffer.getvalue()


def test_print_cve_config_reports_probe_count():
    console, buffer = _console()

    print_cve_config(console, "example.com", ["react2shell"], ["/", "/api"], 10, 5.0, False)
    output = buffer.getvalue()

    assert "react2shell" in output
    assert "/api" in output
    assert "off" in output


def test_print_cve_catalog_lists_registered_scanners():
    console, buffer = _console()

    print_cve_catalog(console, {"react2shell": React2ShellScanner})
    output = buffer.getvalue()

    assert "react2shell" in output
    assert "CVE-2025-55182" in output
    assert "CRITICAL" in output
