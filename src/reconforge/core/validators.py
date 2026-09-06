from pathlib import Path

import re
import ipaddress

from reconforge.core.config import ScanConfig
from reconforge.core.exceptions import (
    InvalidPortRangeError,
    InvalidWordlistError,
    InvalidOutputError,
    InvalidTargetError,
)

# ------ Validation Input ------- #

hostname_label = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

def validate_target(target: str) -> None:
    if not target or not target.strip():
        raise InvalidTargetError("Target cannot be empty")

    target = target.strip()

    if "://" in target:
        raise InvalidTargetError(f"Target must be a hostname or IP: {target!r}")

    try:
        ipaddress.ip_address(target)
        return
    except ValueError:
        pass

    hostname = target

    if hostname[-1] == ".":
        hostname = hostname[:-1]

    if len(hostname) > 253:
        raise InvalidTargetError(f"Invalid hostname lenght: {target!r}")

    for words in hostname.split("."):
        if not hostname_label.match(words):
            raise InvalidTargetError(f"Invalid hostname Label {words!r} in target {target!r}")

        
def validate_port_range(ports: str) -> None: 
    pass


def validate_wordlist(wordlist: Path) -> None:  
    pass


def validate_output(output: Path) -> None:  
    pass


# ------- Orchestration Fonctions --------- #


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
