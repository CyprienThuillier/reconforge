import pytest

from reconforge.core import validators as validators_module
from reconforge.core.exceptions import (
    InvalidPortRangeError,
    InvalidTargetError,
    InvalidWordlistError,
)
from reconforge.core.validators import validate_port, validate_target, validate_wordlist

# --- validate_target ---------------------------------------------------


def test_validate_target_accepts_valid_hostname():
    validate_target("example.com")


def test_validate_target_accepts_valid_ip():
    validate_target("192.168.1.1")


def test_validate_target_accepts_private_ip():
    validate_target("127.0.0.1")


def test_validate_target_rejects_empty_string():
    with pytest.raises(InvalidTargetError):
        validate_target("")


def test_validate_target_rejects_url_scheme():
    with pytest.raises(InvalidTargetError):
        validate_target("http://example.com")


def test_validate_target_rejects_invalid_hostname_label():
    with pytest.raises(InvalidTargetError):
        validate_target("-invalid.example.com")


# --- validate_port -------------------------------------------------------


def test_validate_port_accepts_valid_range():
    validate_port("1-1000")


def test_validate_port_accepts_valid_list():
    validate_port("80,443,8080")


def test_validate_port_accepts_single_port():
    validate_port("443")


def test_validate_port_rejects_out_of_bounds_range():
    with pytest.raises(InvalidPortRangeError):
        validate_port("0-70000")


def test_validate_port_rejects_reversed_range():
    with pytest.raises(InvalidPortRangeError):
        validate_port("5000-80")


def test_validate_port_rejects_invalid_format():
    with pytest.raises(InvalidPortRangeError):
        validate_port("abc")


def test_validate_port_rejects_dangling_dash():
    with pytest.raises(InvalidPortRangeError):
        validate_port("10-")


def test_validate_port_rejects_leading_dash():
    with pytest.raises(InvalidPortRangeError):
        validate_port("-10")


# --- validate_wordlist -----------------------------------------------------


def test_validate_wordlist_accepts_valid_file(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nroot\n", encoding="utf-8")

    validate_wordlist(wordlist)


def test_validate_wordlist_rejects_missing_file(tmp_path):
    with pytest.raises(InvalidWordlistError):
        validate_wordlist(tmp_path / "does-not-exist.txt")


def test_validate_wordlist_rejects_directory(tmp_path):
    with pytest.raises(InvalidWordlistError):
        validate_wordlist(tmp_path)


def test_validate_wordlist_rejects_empty_file(tmp_path):
    wordlist = tmp_path / "empty.txt"
    wordlist.write_text("", encoding="utf-8")

    with pytest.raises(InvalidWordlistError):
        validate_wordlist(wordlist)


def test_validate_wordlist_rejects_whitespace_only_file(tmp_path):
    wordlist = tmp_path / "blank.txt"
    wordlist.write_text("\n\n   \n", encoding="utf-8")

    with pytest.raises(InvalidWordlistError):
        validate_wordlist(wordlist)


def test_validate_wordlist_rejects_oversized_file(tmp_path, monkeypatch):
    monkeypatch.setattr(validators_module, "max_wordlist_size_bytes", 10)

    wordlist = tmp_path / "too-big.txt"
    wordlist.write_text("this line is longer than ten bytes\n", encoding="utf-8")

    with pytest.raises(InvalidWordlistError):
        validate_wordlist(wordlist)
