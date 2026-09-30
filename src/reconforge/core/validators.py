import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from reconforge.core.exceptions import (
    InvalidOutputError,
    InvalidPathError,
    InvalidPortRangeError,
    InvalidTargetError,
    InvalidUrlError,
    InvalidWordlistError,
)

# ------ Validation Input ------- #

hostname_label = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
max_wordlist_size_bytes = 500 * 1024 * 1024
allowed_url_schemes = ("http", "https")
default_url_scheme = "https"
forbidden_path_characters = re.compile(r"[\x00-\x1f\x7f]")


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
        raise InvalidWordlistError(f"Wordlist cannot be empty: {wordlist!r}")

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


def validate_output(output: Path | None) -> None:
    if output is None:
        return

    resolved_o = output.expanduser().resolve()

    if resolved_o.is_dir():
        final_o = resolved_o / "output.log"
    else:
        final_o = resolved_o

    if not final_o.parent.exists():
        raise InvalidOutputError(f"Output directory '{final_o.parent}' does not exist.")

    if not os.access(final_o.parent, os.W_OK):
        raise InvalidOutputError(f"No write permission on directory '{final_o.parent}'.")

    if final_o.exists():
        raise InvalidOutputError(f"Output file '{final_o}' already exits.")


def normalize_url(url: str) -> str:
    candidate = url.strip()
    if not candidate:
        raise InvalidUrlError("URL cannot be empty")

    if "://" not in candidate:
        return f"{default_url_scheme}://{candidate}"
    return candidate


def validate_url(url: str) -> None:
    normalized = normalize_url(url)

    try:
        parsed = urlsplit(normalized)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise InvalidUrlError(f"Malformed URL: {url!r}") from error

    if parsed.scheme not in allowed_url_schemes:
        raise InvalidUrlError(f"URL scheme must be one of {'/'.join(allowed_url_schemes)}: {url!r}")

    if not hostname:
        raise InvalidUrlError(f"URL has no host: {url!r}")

    if parsed.username or parsed.password:
        raise InvalidUrlError(f"URL must not embed credentials: {url!r}")

    try:
        validate_target(hostname)
    except InvalidTargetError as error:
        raise InvalidUrlError(f"Invalid URL host {hostname!r} in {url!r}") from error

    if port is not None and not (1 <= port <= 65535):
        raise InvalidUrlError(f"URL port out of bounds: {url!r}")


def validate_path(path: str) -> None:
    candidate = path.strip()

    if not candidate:
        raise InvalidPathError("Path cannot be empty")

    if not candidate.startswith("/"):
        raise InvalidPathError(f"Path must start with '/': {path!r}")

    if forbidden_path_characters.search(candidate):
        raise InvalidPathError(f"Path must not contain control characters: {path!r}")
