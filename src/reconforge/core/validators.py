import ipaddress
import os
import re
from pathlib import Path

from reconforge.core.exceptions import (
    InvalidPortRangeError,
    InvalidTargetError,
    InvalidWordlistError,
)

# ------ Validation Input ------- #

hostname_label = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
max_wordlist_size_bytes = 500 * 1024 * 1024


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
        start_str, end_str = port_range

        if not start_str.isdigit() or not end_str.isdigit():
            raise InvalidPortRangeError(f"Invalid port range format: {ports!r}")
        start, end = int(start_str), int(end_str)

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
    if not wordlist.exists():
        raise InvalidWordlistError(f"Wordlist not found: {wordlist!r}")

    if not wordlist.is_file():
        raise InvalidWordlistError(f"Wordlist is not a file: {wordlist!r}")

    if not os.access(wordlist, os.R_OK):
        raise InvalidWordlistError(f"Wordlist is not readable: {wordlist!r}")

    size = wordlist.stat().st_size
    if size == 0:
        raise InvalidWordlistError(f"Wordlist is empty: {wordlist!r}")

    if size > max_wordlist_size_bytes:
        raise InvalidWordlistError(
            f"Wordlist exceeds max size of {max_wordlist_size_bytes} bytes: {wordlist!r}"
        )

    content = False
    with wordlist.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                content = True
                break

    if not content:
        raise InvalidWordlistError(f"Wordlist contain no usable entries: {wordlist!r}")


def validate_output(output: Path) -> None:
    pass
