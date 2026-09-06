from pathlib import Path

from reconforge.core.config import ScanConfig
from reconforge.core.exceptions import (
    InvalidPortRangeError,
    InvalidWordlistError,
)

# ------ Validation Input ------- #


def validate_target(target: str) -> None:  # Logique a coder
    pass


def validate_port_range(ports: str) -> None:  # Logique a coder
    pass


def validate_wordlist(wordlist: Path) -> None:  # Logique a coder
    pass


def validate_output(output: Path) -> None:  # Logique a coder
    pass


# ------- Fonction d'orchestrage --------- #


def validate_pscan_config(config: ScanConfig) -> None:

    validate_target(config.target)

    if config.ports is None:
        raise InvalidPortRangeError("Port range is required for pscan")

    validate_port_range(config.ports)

    if config.output is not None:
        validate_output(config.output)


def validate_enum_config(config: ScanConfig) -> None:

    validate_target(config.target)

    if config.wordlist is None:
        raise InvalidWordlistError("Wordlist is required for enum")

    validate_wordlist(config.wordlist)

    if config.output is not None:
        validate_output(config.output)
