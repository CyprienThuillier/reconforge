# tests/modules/test_subdomain_wordlist.py
from pathlib import Path

import pytest

from reconforge.modules.subdomain_enum import build_names, load_labels
from reconforge.modules.subdomain_enum.wordlist import is_valid_label


@pytest.mark.parametrize("label", ["www", "api-v2", "_dmarc", "a", "x" * 63])
def test_is_valid_label_accepts(label: str) -> None:
    assert is_valid_label(label)


@pytest.mark.parametrize("label", ["", "-bad", "bad-", "has space", "a.b", "x" * 64, "Ünï"])
def test_is_valid_label_rejects(label: str) -> None:
    assert not is_valid_label(label)


def test_load_labels_filters_and_normalizes(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("WWW\n# comment\n\n  mail  \n-bad\napi\n", encoding="utf-8")

    assert list(load_labels(wordlist)) == ["www", "mail", "api"]


def test_build_names_deduplicates_and_keeps_order() -> None:
    names = build_names(["www", "api", "www", "mail"], "example.com")

    assert names == ["www.example.com", "api.example.com", "mail.example.com"]
