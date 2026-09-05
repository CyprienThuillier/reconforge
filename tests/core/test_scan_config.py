import pytest
from pydantic import ValidationError

from reconforge.core.enums import Modules
from reconforge.core.scan_config import ScanConfig


def test_scan_config_valid_construction():
    config = ScanConfig(
        target="example.com",
        modules=["ports", "subdomains"],
        ports=["80,443"],
        wordlist=None,
        output=None,
    )
    assert config.target == "example.com"
    assert config.modules == [Modules.PORT_SCAN, Modules.SUBDOMAIN_ENUM]
    assert config.ports == ["80,443"]
    assert config.wordlist is None
    assert config.output is None


def test_scan_config_accepts_valid_ip_target():
    config = ScanConfig(
        target="192.168.1.1", modules=["ports"], ports=[], wordlist=None, output=None
    )
    assert config.target == "192.168.1.1"


def test_target_rejects_invalid_value():
    with pytest.raises(ValidationError, match="invalid target"):
        ScanConfig(
            target="not_a_valid_target!!",
            modules=["ports"],
            ports=[],
            wordlist=None,
            output=None,
        )


def test_ports_accepts_valid_ranges():
    config = ScanConfig(
        target="example.com",
        modules=["ports"],
        ports=["80,443,8000-8100"],
        wordlist=None,
        output=None,
    )
    assert config.ports == ["80,443,8000-8100"]


def test_ports_rejects_invalid_syntax():
    with pytest.raises(ValidationError, match="invalid port range syntax"):
        ScanConfig(
            target="example.com",
            modules=["ports"],
            ports=["abc"],
            wordlist=None,
            output=None,
        )


def test_ports_rejects_out_of_range_value():
    with pytest.raises(ValidationError, match="out of range"):
        ScanConfig(
            target="example.com",
            modules=["ports"],
            ports=["99999"],
            wordlist=None,
            output=None,
        )


def test_ports_rejects_inverted_range():
    with pytest.raises(ValidationError, match="invalid range order"):
        ScanConfig(
            target="example.com",
            modules=["ports"],
            ports=["100-50"],
            wordlist=None,
            output=None,
        )


def test_wordlist_accepts_existing_file(tmp_path):
    wordlist_file = tmp_path / "words.txt"
    wordlist_file.write_text("admin\nlogin\n")

    config = ScanConfig(
        target="example.com",
        modules=["subdomains"],
        ports=[],
        wordlist=wordlist_file,
        output=None,
    )
    assert config.wordlist == wordlist_file


def test_wordlist_rejects_missing_file(tmp_path):
    missing = tmp_path / "does_not_exist.txt"
    with pytest.raises(ValidationError, match="wordlist not found"):
        ScanConfig(
            target="example.com",
            modules=["subdomains"],
            ports=[],
            wordlist=missing,
            output=None,
        )


def test_modules_rejects_unknown_value():
    with pytest.raises(ValidationError):
        ScanConfig(
            target="example.com",
            modules=["not_a_real_module"],
            ports=[],
            wordlist=None,
            output=None,
        )
