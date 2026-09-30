from pathlib import Path

import pytest

from reconforge.core.config import (
    ScanConfig,
    default_path_for,
    parse_paths,
    parse_ports,
)
from reconforge.core.exceptions import (
    InvalidPathError,
    InvalidTargetError,
    InvalidUrlError,
    InvalidWordlistError,
)


def test_scan_config_target_only():
    config = ScanConfig(target="example.com")

    assert config.target == "example.com"
    assert config.ports is None
    assert config.scan_type is None
    assert config.mode is None
    assert config.wordlist is None
    assert config.verbose is False
    assert config.output is None


def test_scan_config_pscan_fields():
    config = ScanConfig(
        target="example.com",
        ports=[80, 443],
        scan_type="syn",
        verbose=True,
        output=Path("report.json"),
    )

    assert config.target == "example.com"
    assert config.ports == [80, 443]
    assert config.scan_type == "syn"
    assert config.mode is None
    assert config.wordlist is None
    assert config.verbose is True
    assert config.output == Path("report.json")


def test_scan_config_enum_fields():
    config = ScanConfig(
        target="example.com",
        mode="subdomains",
        wordlist=Path("wordlists/common.txt"),
        verbose=False,
    )

    assert config.target == "example.com"
    assert config.mode == "subdomains"
    assert config.wordlist == Path("wordlists/common.txt")
    assert config.ports is None
    assert config.scan_type is None
    assert config.verbose is False


def test_scan_config_verbose_defaults_to_false():
    config = ScanConfig(target="example.com")
    assert config.verbose is False


def test_scan_config_verbose_stored_when_true():
    config = ScanConfig(target="example.com", verbose=True)
    assert config.verbose is True


# --- parse_ports -------------------------------------------------------


def test_parse_ports_range():
    assert parse_ports("20-25") == [20, 21, 22, 23, 24, 25]


def test_parse_ports_list():
    assert parse_ports("80,443,8080") == [80, 443, 8080]


def test_parse_ports_single():
    assert parse_ports("443") == [443]


# --- ScanConfig.port_scan ------------------------------------------------


def test_port_scan_builds_config_with_parsed_ports():
    config = ScanConfig.port_scan(target="example.com", ports="20-25")

    assert config.target == "example.com"
    assert config.ports == [20, 21, 22, 23, 24, 25]


def test_port_scan_rejects_invalid_target():
    with pytest.raises(InvalidTargetError):
        ScanConfig.port_scan(target="http://example.com", ports="1-1000")


# --- ScanConfig.enum ------------------------------------------------------


def test_enum_builds_config_with_wordlist(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")

    config = ScanConfig.enum(target="example.com", wordlist=wordlist)

    assert config.target == "example.com"
    assert config.wordlist == wordlist


def test_enum_rejects_invalid_wordlist(tmp_path):
    with pytest.raises(InvalidWordlistError):
        ScanConfig.enum(target="example.com", wordlist=tmp_path / "missing.txt")


# --- default_path_for ------------------------------------------------------


def test_default_path_for_root_targets():
    assert default_path_for("https://example.com") == "/"
    assert default_path_for("https://example.com/") == "/"


def test_default_path_for_specific_path_is_empty():
    assert default_path_for("https://example.com/admin") == ""


# --- parse_paths -----------------------------------------------------------


def test_parse_paths_defaults_to_target_path():
    assert parse_paths(None, "https://example.com") == ["/"]
    assert parse_paths(None, "https://example.com/admin") == [""]


def test_parse_paths_normalizes_and_splits_selection():
    assert parse_paths(["api/v1", " "], "https://example.com") == ["/api/v1"]
    assert parse_paths("/,/api", "https://example.com") == ["/", "/api"]


def test_parse_paths_rejects_crlf_injection():
    with pytest.raises(InvalidPathError):
        parse_paths(["/\r\nX-Injected: 1"], "https://example.com")


# --- ScanConfig.cve_scan ---------------------------------------------------


def test_cve_scan_normalizes_target_and_defaults_to_every_cve():
    config = ScanConfig.cve_scan(target="example.com")

    assert config.target == "https://example.com"
    assert config.cves == []
    assert config.paths == ["/"]
    assert config.verbose is False
    assert config.output is None


def test_cve_scan_keeps_scheme_port_cves_and_paths():
    config = ScanConfig.cve_scan(
        target="http://example.com:8080", cves=["react2shell"], paths=["/", "/api"]
    )

    assert config.target == "http://example.com:8080"
    assert config.cves == ["react2shell"]
    assert config.paths == ["/", "/api"]


def test_cve_scan_probes_given_target_path_as_is():
    assert ScanConfig.cve_scan(target="https://example.com/admin").paths == [""]


def test_cve_scan_stores_verbose_and_output(tmp_path):
    report = tmp_path / "report.log"

    config = ScanConfig.cve_scan(target="https://example.com", verbose=True, output=report)

    assert config.verbose is True
    assert config.output == report


def test_cve_scan_rejects_unusable_target_or_path():
    with pytest.raises(InvalidUrlError):
        ScanConfig.cve_scan(target="file:///etc/passwd")

    with pytest.raises(InvalidPathError):
        ScanConfig.cve_scan(target="https://example.com", paths=["bad\npath"])
