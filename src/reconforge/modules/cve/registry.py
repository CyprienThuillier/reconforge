from collections.abc import Iterable

from reconforge.core.exceptions import InvalidCveError
from reconforge.modules.cve.base import CveScanner
from reconforge.modules.cve.react2shell import React2ShellScanner

ALL_KEYWORD = "all"

CVE_SCANNERS: dict[str, type[CveScanner]] = {
    "react2shell": React2ShellScanner,
}


def available_cves() -> list[str]:
    return sorted(CVE_SCANNERS)


def resolve_scanners(keys: Iterable[str] | None = None) -> list[CveScanner]:
    requested = [key.strip().lower() for key in keys or [] if key.strip()]

    if not requested or ALL_KEYWORD in requested:
        requested = available_cves()

    unknown = [key for key in requested if key not in CVE_SCANNERS]
    if unknown:
        valid = ", ".join(available_cves())
        raise InvalidCveError(f"Unknown CVE(s): {', '.join(unknown)}. Available: {valid}")

    return [CVE_SCANNERS[key]() for key in dict.fromkeys(requested)]
