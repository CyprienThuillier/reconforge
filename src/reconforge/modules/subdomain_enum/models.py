from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum

DEFAULT_TIMEOUT = 2.0
DEFAULT_RETRIES = 3
DEFAULT_CONCURRENCY = 100
DEFAULT_NAMESERVERS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
DEFAULT_RDTYPES: tuple[str, ...] = ("A",)
RETRY_DELAY = 0.2


class DnsStatus(str, Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    NO_DATA = "no_data"
    RETRY = "retry"
    FAILED = "failed"
    ERROR = "error"


@dataclass(frozen=True)
class SubdomainResult:
    name: str
    status: DnsStatus
    records: dict[str, list[str]] = field(default_factory=dict)


SubdomainProgressCallback = Callable[[SubdomainResult], None]
SubdomainProbe = Callable[[str], Awaitable[SubdomainResult]]
