# tests/modules/test_engine.py
import asyncio

import pytest

from reconforge.modules.port_scanning import PortResult, PortState, scan_ports


@pytest.mark.asyncio
async def test_scan_ports_preserves_input_order() -> None:
    async def _fake_probe(target: str, port: int, timeout: float) -> PortResult:
        await asyncio.sleep(0.01 * (port % 3))
        return PortResult(port=port, state=PortState.OPEN)

    ports = [80, 443, 22, 8080, 21]
    results = await scan_ports(_fake_probe, "127.0.0.1", ports)

    assert [result.port for result in results] == ports


@pytest.mark.asyncio
async def test_scan_ports_respects_concurrency_limit() -> None:
    concurrent_count = 0
    max_concurrent = 0
    lock = asyncio.Lock()

    async def _fake_probe(target: str, port: int, timeout: float) -> PortResult:
        nonlocal concurrent_count, max_concurrent
        async with lock:
            concurrent_count += 1
            max_concurrent = max(max_concurrent, concurrent_count)

        await asyncio.sleep(0.05)

        async with lock:
            concurrent_count -= 1

        return PortResult(port=port, state=PortState.OPEN)

    ports = list(range(1, 21))
    await scan_ports(_fake_probe, "127.0.0.1", ports, concurrency=5)

    assert max_concurrent <= 5
    assert max_concurrent > 1


@pytest.mark.asyncio
async def test_scan_ports_calls_on_result_for_each_port() -> None:
    async def _fake_probe(target: str, port: int, timeout: float) -> PortResult:
        return PortResult(port=port, state=PortState.CLOSED)

    seen: list[int] = []

    def _record(result: PortResult) -> None:
        seen.append(result.port)

    ports = [22, 80, 443]
    await scan_ports(_fake_probe, "127.0.0.1", ports, on_result=_record)

    assert sorted(seen) == sorted(ports)


@pytest.mark.asyncio
async def test_scan_ports_passes_target_and_timeout_to_probe() -> None:
    calls: list[tuple[str, int, float]] = []

    async def _fake_probe(target: str, port: int, timeout: float) -> PortResult:
        calls.append((target, port, timeout))
        return PortResult(port=port, state=PortState.OPEN)

    await scan_ports(_fake_probe, "example.com", [80], timeout=2.5)

    assert calls == [("example.com", 80, 2.5)]
