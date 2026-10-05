import asyncio
from collections.abc import Sequence

from reconforge.modules.subdomain_enum.models import (
    DEFAULT_CONCURRENCY,
    SubdomainProbe,
    SubdomainProgressCallback,
    SubdomainResult,
)


async def enumerate_subdomains(
    probe: SubdomainProbe,
    names: Sequence[str],
    concurrency: int = DEFAULT_CONCURRENCY,
    on_result: SubdomainProgressCallback | None = None,
) -> list[SubdomainResult]:
    semaphore = asyncio.Semaphore(concurrency)

    async def bounded_resolve(name: str) -> SubdomainResult:
        async with semaphore:
            result = await probe(name)

        if on_result is not None:
            on_result(result)

        return result

    tasks = [bounded_resolve(name) for name in names]
    return list(await asyncio.gather(*tasks))
