# tests/modules/test_port_scanning.py
import asyncio
import socket
from collections.abc import AsyncIterator

import pytest

from reconforge.modules.port_scanning import (
    DEFAULT_CONNECT_TIMEOUT,
    PortResult,
    PortState,
    scan_port_connect,
    scan_ports_connect,
)


async def _accept_and_close(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.close()
    await writer.wait_closed()


@pytest.fixture
async def listening_port() -> AsyncIterator[int]:
    server = await asyncio.start_server(_accept_and_close, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield port


def _free_closed_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# --- scan_port_connect ---------------------------------------------------


@pytest.mark.asyncio
async def test_scan_port_connect_detects_open_port(listening_port: int) -> None:
    result = await scan_port_connect("127.0.0.1", listening_port)

    assert result.port == listening_port
    assert result.state == PortState.OPEN


@pytest.mark.asyncio
async def test_scan_port_connect_detects_closed_port() -> None:
    port = _free_closed_port()

    result = await scan_port_connect("127.0.0.1", port)

    assert result.state == PortState.CLOSED


@pytest.mark.asyncio
async def test_scan_port_connect_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _hang(host: str, port: int) -> tuple[None, None]:
        await asyncio.sleep(10)
        return None, None

    monkeypatch.setattr(asyncio, "open_connection", _hang)

    result = await scan_port_connect("127.0.0.1", 9999, timeout=0.05)

    assert result.state == PortState.CLOSED


# --- scan_ports_connect ----------------------------------------------------


@pytest.mark.asyncio
async def test_scan_ports_connect_preserves_input_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_scan(
        target: str, port: int, timeout: float = DEFAULT_CONNECT_TIMEOUT
    ) -> PortResult:
        await asyncio.sleep(0.01 * (port % 3))
        return PortResult(port=port, state=PortState.OPEN)

    monkeypatch.setattr("reconforge.modules.port_scanning.scan_port_connect", _fake_scan)

    ports = [80, 443, 22, 8080, 21]
    results = await scan_ports_connect("127.0.0.1", ports)

    assert [result.port for result in results] == ports


@pytest.mark.asyncio
async def test_scan_ports_connect_respects_concurrency_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    concurrent_count = 0
    max_concurrent = 0
    lock = asyncio.Lock()

    async def _fake_scan(
        target: str, port: int, timeout: float = DEFAULT_CONNECT_TIMEOUT
    ) -> PortResult:
        nonlocal concurrent_count, max_concurrent
        async with lock:
            concurrent_count += 1
            max_concurrent = max(max_concurrent, concurrent_count)

        await asyncio.sleep(0.05)

        async with lock:
            concurrent_count -= 1

        return PortResult(port=port, state=PortState.OPEN)

    monkeypatch.setattr("reconforge.modules.port_scanning.scan_port_connect", _fake_scan)

    ports = list(range(1, 21))
    await scan_ports_connect("127.0.0.1", ports, concurrency=5)

    assert max_concurrent <= 5
    assert max_concurrent > 1
