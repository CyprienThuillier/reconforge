from pathlib import Path

from reconforge.core.config import ScanConfig


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
        ports="1-10000",
        scan_type="syn",
        verbose=True,
        output=Path("report.json"),
    )

    assert config.target == "example.com"
    assert config.ports == "1-10000"
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
