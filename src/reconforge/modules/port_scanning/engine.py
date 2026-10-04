import asyncio

from reconforge.modules.port_scanning.models import (
    DEFAULT_CONCURRENCY,
    DEFAULT_CONNECT_TIMEOUT,
    PortProbe,
    PortResult,
    ProgressCallback,
)


async def scan_ports(
    probe: PortProbe,
    target: str,
    ports: list[int],
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
    on_result: ProgressCallback | None = None,
) -> list[PortResult]:
    semaphore = asyncio.Semaphore(concurrency)

    async def bounded_scan(port: int) -> PortResult:
        async with semaphore:
            result = await probe(target, port, timeout)

        if on_result is not None:
            on_result(result)

        return result

    tasks = [bounded_scan(port) for port in ports]
    return list(await asyncio.gather(*tasks))
