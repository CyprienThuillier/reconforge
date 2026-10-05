import re
from collections.abc import Iterable, Iterator
from pathlib import Path

LABEL_PATTERN = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


def is_valid_label(label: str) -> bool:
    return LABEL_PATTERN.fullmatch(label) is not None


def load_labels(wordlist_path: Path) -> Iterator[str]:
    """Yield lowercase, valid DNS labels from a wordlist (comments and blanks skipped)."""
    with wordlist_path.open("r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            label = line.strip().lower()
            if label and not label.startswith("#") and is_valid_label(label):
                yield label


def build_names(labels: Iterable[str], domain: str) -> list[str]:
    """Build fully-qualified names, deduplicated while preserving wordlist order."""
    return list(dict.fromkeys(f"{label}.{domain}" for label in labels))
