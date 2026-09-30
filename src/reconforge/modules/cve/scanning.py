import asyncio
from collections.abc import Callable, Sequence

from reconforge.modules.cve.base import (
    DEFAULT_CONCURRENCY,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_VERIFY_SSL,
    CveResult,
    CveScanner,
    build_client,
)

DEFAULT_PATHS = ("/",)

ProgressCallback = Callable[[CveResult], None]


def build_probe_urls(target: str, paths: Sequence[str]) -> list[str]:
    base = target.rstrip("/")
    return [f"{base}{path}" for path in paths]


async def scan_cves(
    target: str,
    scanners: Sequence[CveScanner],
    paths: Sequence[str] = DEFAULT_PATHS,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_REQUEST_TIMEOUT,
    verify_ssl: bool = DEFAULT_VERIFY_SSL,
    on_result: ProgressCallback | None = None,
) -> list[CveResult]:
    semaphore = asyncio.Semaphore(concurrency)
    jobs = [(scanner, url) for scanner in scanners for url in build_probe_urls(target, paths)]

    async def bounded_scan(scanner: CveScanner, url: str) -> CveResult:
        async with semaphore:
            result = await scanner.check(url, client)

        if on_result is not None:
            on_result(result)

        return result

    async with build_client(timeout=timeout, verify_ssl=verify_ssl) as client:
        tasks = [bounded_scan(scanner, url) for scanner, url in jobs]
        return await asyncio.gather(*tasks)
