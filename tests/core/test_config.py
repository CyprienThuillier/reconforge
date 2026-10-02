from pathlib import Path

import pytest

from reconforge.core.config import ScanConfig, parse_ports
from reconforge.core.exceptions import InvalidTargetError, InvalidWordlistError


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
