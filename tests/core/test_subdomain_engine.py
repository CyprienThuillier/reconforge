# tests/modules/test_subdomain_engine.py
import asyncio

import pytest

from reconforge.modules.subdomain_enum import DnsStatus, SubdomainResult, enumerate_subdomains


@pytest.mark.asyncio
async def test_enumerate_preserves_input_order() -> None:
    async def _probe(name: str) -> SubdomainResult:
        await asyncio.sleep(0.01 * (len(name) % 3))
        return SubdomainResult(name=name, status=DnsStatus.NOT_FOUND)

    names = ["a.example.com", "bb.example.com", "ccc.example.com", "dddd.example.com"]
    results = await enumerate_subdomains(_probe, names)

    assert [result.name for result in results] == names


@pytest.mark.asyncio
async def test_enumerate_respects_concurrency_limit() -> None:
    current = 0
    peak = 0

    async def _probe(name: str) -> SubdomainResult:
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        await asyncio.sleep(0.05)
        current -= 1
        return SubdomainResult(name=name, status=DnsStatus.NOT_FOUND)

    names = [f"w{i}.example.com" for i in range(20)]
    await enumerate_subdomains(_probe, names, concurrency=5)

    assert 1 < peak <= 5


@pytest.mark.asyncio
async def test_enumerate_calls_on_result_for_each_name() -> None:
    async def _probe(name: str) -> SubdomainResult:
        return SubdomainResult(name=name, status=DnsStatus.FOUND, records={"A": ["1.1.1.1"]})

    seen: list[str] = []
    names = ["a.example.com", "b.example.com"]
    await enumerate_subdomains(_probe, names, on_result=lambda r: seen.append(r.name))

    assert sorted(seen) == sorted(names)
