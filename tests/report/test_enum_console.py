import io

from rich.console import Console

from reconforge.core.enums import EnumType
from reconforge.modules.subdomain_enum import DnsStatus, SubdomainResult
from reconforge.report.enum_console import (
    build_enum_table,
    format_records,
    print_enum_banner,
    print_enum_results,
    print_enum_summary,
    print_found,
)


def _results() -> list[SubdomainResult]:
    return [
        SubdomainResult("www.example.com", DnsStatus.FOUND, {"A": ["1.2.3.4"], "AAAA": ["::1"]}),
        SubdomainResult("old.example.com", DnsStatus.NOT_FOUND),
        SubdomainResult("api.example.com", DnsStatus.FOUND, {"A": ["5.6.7.8", "5.6.7.9"]}),
        SubdomainResult("slow.example.com", DnsStatus.FAILED),
    ]


def _console() -> tuple[Console, io.StringIO]:
    buffer = io.StringIO()
    return Console(file=buffer, width=120), buffer


def test_format_records_joins_types_and_values() -> None:
    assert format_records({"A": ["1.1.1.1", "2.2.2.2"], "AAAA": ["::1"]}) == (
        "A: 1.1.1.1, 2.2.2.2  AAAA: ::1"
    )


def test_build_enum_table_has_one_row_per_record_type_of_found_names() -> None:
    table = build_enum_table("example.com", _results())

    assert table.row_count == 3  # www (A, AAAA) + api (A)


def test_print_enum_results_reports_when_nothing_found() -> None:
    console, buffer = _console()

    print_enum_results(
        console, "example.com", [SubdomainResult("a.example.com", DnsStatus.NOT_FOUND)]
    )

    assert "No subdomains found" in buffer.getvalue()


def test_print_enum_summary_reports_counts() -> None:
    console, buffer = _console()

    print_enum_summary(console, _results(), 2.0, verbose=False, concurrency=100, timeout=2.0)

    output = buffer.getvalue()
    assert "2 found" in output
    assert "2 unresolved" in output
    assert "names/s" not in output


def test_print_enum_summary_verbose_adds_statistics() -> None:
    console, buffer = _console()

    print_enum_summary(console, _results(), 2.0, verbose=True, concurrency=100, timeout=2.0)

    assert "names/s" in buffer.getvalue()


def test_print_found_shows_name_and_records() -> None:
    console, buffer = _console()

    print_found(console, _results()[0])

    output = buffer.getvalue()
    assert "www.example.com" in output
    assert "1.2.3.4" in output


def test_print_enum_banner_shows_target_and_mode() -> None:
    console, buffer = _console()

    print_enum_banner(console, "example.com", EnumType.SUBDOMAIN)

    output = buffer.getvalue()
    assert "example.com" in output
    assert "subdomain enumeration" in output
