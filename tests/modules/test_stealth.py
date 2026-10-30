import asyncio
import socket
from collections.abc import Callable
from unittest.mock import MagicMock, patch

import pytest

from reconforge.core.exceptions import InsufficientPrivilegesError, TargetResolutionError
from reconforge.modules.port_scanning.models import PortState
from reconforge.modules.port_scanning.stealth import (
    StealthScanner,
    _stealth_session,
    fin_session,
    null_session,
    xmas_session,
)


class MockStealthTransport:
    def __init__(self) -> None:
        self.sent_ports: list[int] = []
        self.callback: Callable[[int, PortState], None] | None = None

    def start_sniffer(self, callback: Callable[[int, PortState], None]) -> None:
        self.callback = callback

    async def wait_ready(self) -> None:
        pass

    def send_packet(self, dport: int) -> None:
        self.sent_ports.append(dport)
        if self.callback:
            # Simulate a RST response received for closed port
            asyncio.get_running_loop().call_soon(self.callback, dport, PortState.CLOSED)

    def stop(self) -> None:
        pass


@pytest.mark.asyncio
async def test_stealth_scanner_detects_closed_on_rst() -> None:
    transport = MockStealthTransport()
    scanner = StealthScanner(transport)
    transport.start_sniffer(scanner._sniffer_callback)

    result = await scanner.scan_port("127.0.0.1", 80, timeout=1.0)
    assert result.state == PortState.CLOSED
    assert 80 in transport.sent_ports


@pytest.mark.asyncio
async def test_stealth_scanner_times_out_as_open_filtered() -> None:
    class MockTimeoutTransport(MockStealthTransport):
        def send_packet(self, dport: int) -> None:
            self.sent_ports.append(dport)
            # No callback = silence from host = open or filtered per RFC 793

    transport = MockTimeoutTransport()
    scanner = StealthScanner(transport)
    transport.start_sniffer(scanner._sniffer_callback)

    result = await scanner.scan_port("127.0.0.1", 80, timeout=0.05)
    assert result.state == PortState.OPEN_FILTERED
    assert 80 in transport.sent_ports


@pytest.mark.asyncio
async def test_stealth_session_requires_root() -> None:
    with (
        patch("os.geteuid", return_value=1000),
        pytest.raises(InsufficientPrivilegesError, match="root"),
    ):
        async with _stealth_session("127.0.0.1", flags="F"):
            pass


@pytest.mark.asyncio
async def test_stealth_session_handles_resolution_failure() -> None:
    with (
        patch("os.geteuid", return_value=0),
        patch("socket.gethostbyname", side_effect=socket.gaierror("lookup failed")),
        pytest.raises(TargetResolutionError, match="Cannot resolve target"),
    ):
        async with _stealth_session("nonexistent.invalid", flags="F"):
            pass


@pytest.mark.asyncio
async def test_stealth_session_lifecycle() -> None:
    mock_transport = MagicMock()
    mock_transport.wait_ready = MagicMock(side_effect=lambda: asyncio.sleep(0))

    with (
        patch("os.geteuid", return_value=0),
        patch("socket.gethostbyname", return_value="127.0.0.1"),
        patch(
            "reconforge.modules.port_scanning.stealth_transport.StealthTransport",
            return_value=mock_transport,
        ) as mock_cls,
    ):
        async with fin_session("127.0.0.1") as probe:
            assert callable(probe)
            mock_cls.assert_called_once_with("127.0.0.1", flags="F")
            mock_transport.start_sniffer.assert_called_once()

        mock_transport.stop.assert_called_once()


@pytest.mark.asyncio
async def test_stealth_flag_sessions() -> None:
    mock_transport = MagicMock()
    mock_transport.wait_ready = MagicMock(side_effect=lambda: asyncio.sleep(0))

    with (
        patch("os.geteuid", return_value=0),
        patch("socket.gethostbyname", return_value="127.0.0.1"),
        patch(
            "reconforge.modules.port_scanning.stealth_transport.StealthTransport",
            return_value=mock_transport,
        ) as mock_cls,
    ):
        async with null_session("127.0.0.1"):
            mock_cls.assert_called_with("127.0.0.1", flags="")

        async with xmas_session("127.0.0.1"):
            mock_cls.assert_called_with("127.0.0.1", flags="FPU")
