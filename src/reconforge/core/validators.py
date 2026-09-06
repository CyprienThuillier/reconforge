from pathlib import Path

import re
import ipaddress

from reconforge.core.exceptions import (
    InvalidPortRangeError,
    InvalidWordlistError,
    InvalidOutputError,
    InvalidTargetError,
)

from reconforge.core.config import ScanConfig

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

        
def validate_port(ports: str) -> None:
    if "-" in ports:
        if "," in ports:
            raise InvalidPortRangeError(f"Invalid port range format: {ports!r}")
        port_range = ports.split("-")
        if len(port_range) != 2:
            raise InvalidPortRangeError(f"Invalid port range format: {ports!r}")
        start, end = int(port_range[0]), int(port_range[1])
        if start < 1 or end > 65535 or start > end:
            raise InvalidPortRangeError(f"Port range out of bounds: {ports!r}")
    elif "," in ports:
        for port in ports.split(","):
            if not port.isdigit() or not (1 <= int(port) <= 65535):
                raise InvalidPortRangeError(f"Invalid port number: {port!r} in {ports!r}")
    else:
        if not ports.isdigit() or not (1 <= int(ports) <= 65535):
            raise InvalidPortRangeError(f"Invalid port number: {ports!r}")


def validate_wordlist(wordlist: Path) -> None:  
    pass


def validate_output(output: Path) -> None:  
    pass
