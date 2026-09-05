import ipaddress
import re
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from .enums import Modules

ports_range = re.compile(r"^\d+(-\d+)?$")


class ScanConfig(BaseModel):
    target: str
    modules: list[Modules]
    ports: list[str] = Field(default_factory=list)
    wordlist: Path | None = None
    output: Path | None = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
            return value

        except ValueError:
            pass

        domain = re.compile(
            r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)" r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
        )
        if not domain.match(value):
            raise ValueError(f"invalid target: {value!r} is not a valid IP or domain")
        return value

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: list[str]) -> list[str]:
        for val in value:
            for port in val.split(","):
                if not ports_range.match(port):
                    raise ValueError(f"invalid port range syntax: {port!r}")

                bounds = [int(n) for n in port.split("-")]
                if any(not (1 <= n <= 65535) for n in bounds):
                    raise ValueError(f"port out of range [1-65535]: {port!r}")

                if len(bounds) == 2 and bounds[0] > bounds[1]:
                    raise ValueError(f"invalid range order: {port!r}")
        return value

    @field_validator("wordlist")
    @classmethod
    def validate_wordlist(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_file():
            raise ValueError(f"wordlist not found: {value}")
        return value
