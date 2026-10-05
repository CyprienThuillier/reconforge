import asyncio
import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from reconforge.modules.port_scanning.models import PortState
from reconforge.modules.port_scanning.syn import syn_session


async def _accept_and_close(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.close()
    await writer.wait_closed()


@pytest_asyncio.fixture
async def listening_port() -> AsyncIterator[int]:
    server = await asyncio.start_server(_accept_and_close, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield port


@pytest.mark.integration
@pytest.mark.asyncio
async def test_integration_syn_scan(listening_port: int) -> None:
    if os.geteuid() != 0:
        pytest.skip("Integration tests require root privileges")

    async with syn_session("127.0.0.1") as probe:
        result = await probe("127.0.0.1", listening_port, 1.0)

    assert result.state == PortState.OPEN
