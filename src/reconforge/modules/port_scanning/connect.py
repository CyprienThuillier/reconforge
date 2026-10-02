import asyncio

from reconforge.modules.port_scanning.models import (
    DEFAULT_CONCURRENCY,
    DEFAULT_CONNECT_TIMEOUT,
    PortResult,
    PortState,
    ProgressCallback,
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

    except (TimeoutError, ConnectionRefusedError, OSError):
        return PortResult(port=port, state=PortState.CLOSED)

    writer.close()
    await writer.wait_closed()
    return PortResult(port=port, state=PortState.OPEN)


async def scan_ports_connect(
    target: str,
    ports: list[int],
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
    on_result: ProgressCallback | None = None,
) -> list[PortResult]:

    semaphore = asyncio.Semaphore(concurrency)

    async def bounded_scan(port: int) -> PortResult:
        async with semaphore:
            result = await scan_port_connect(target, port, timeout)

        if on_result is not None:
            on_result(result)

        return result

    tasks = [bounded_scan(port) for port in ports]
    return await asyncio.gather(*tasks)
