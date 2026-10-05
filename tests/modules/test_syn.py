import asyncio
from collections.abc import Callable

import pytest

from reconforge.modules.port_scanning.models import PortState
from reconforge.modules.port_scanning.syn import SynScanner


class MockSynTransport:
    def __init__(self) -> None:
        self.sent_ports: list[int] = []
        self.callback: Callable[[int, PortState], None] | None = None

    def start_sniffer(self, callback: Callable[[int, PortState], None]) -> None:
        self.callback = callback

    async def wait_ready(self) -> None:
        pass

    def send_syn(self, dport: int) -> None:
        self.sent_ports.append(dport)
        if self.callback:
            # Simulate an immediate response for testing
            asyncio.get_running_loop().call_soon(self.callback, dport, PortState.OPEN)

    def stop(self) -> None:
        pass


@pytest.mark.asyncio
async def test_syn_scanner_detects_open() -> None:
    transport = MockSynTransport()
    scanner = SynScanner(transport)
    transport.start_sniffer(scanner._sniffer_callback)

    result = await scanner.scan_port("127.0.0.1", 80, timeout=1.0)
    assert result.state == PortState.OPEN
    assert 80 in transport.sent_ports


@pytest.mark.asyncio
async def test_syn_scanner_times_out_as_filtered() -> None:
    class MockTimeoutTransport(MockSynTransport):
        def send_syn(self, dport: int) -> None:
            self.sent_ports.append(dport)
            # No callback = timeout

    transport = MockTimeoutTransport()
    scanner = SynScanner(transport)
    transport.start_sniffer(scanner._sniffer_callback)

    result = await scanner.scan_port("127.0.0.1", 80, timeout=0.05)
    assert result.state == PortState.FILTERED
    assert 80 in transport.sent_ports
