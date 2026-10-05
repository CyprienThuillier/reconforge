import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from reconforge.modules.port_scanning.models import (
    DEFAULT_CONNECT_TIMEOUT,
    PortProbe,
    PortResult,
    PortState,
)


async def scan_port_connect(
    target: str,
    port: int,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
) -> PortResult:

    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=timeout
        )

    except TimeoutError:
        return PortResult(port=port, state=PortState.FILTERED)
    except (ConnectionRefusedError, OSError):
        return PortResult(port=port, state=PortState.CLOSED)

    writer.close()
    await writer.wait_closed()
    return PortResult(port=port, state=PortState.OPEN)


@asynccontextmanager
async def connect_session() -> AsyncIterator[PortProbe]:
    yield scan_port_connect
