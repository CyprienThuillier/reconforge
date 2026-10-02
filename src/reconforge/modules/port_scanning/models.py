from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum

DEFAULT_CONNECT_TIMEOUT = 1.0
DEFAULT_CONCURRENCY = 500


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"


@dataclass(frozen=True)
class PortResult:
    port: int
    state: PortState


ProgressCallback = Callable[[PortResult], None]
PortProbe = Callable[[str, int, float], Awaitable[PortResult]]
