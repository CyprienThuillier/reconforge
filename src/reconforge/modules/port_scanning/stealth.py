import asyncio
import os
import socket
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Protocol

from reconforge.core.exceptions import InsufficientPrivilegesError, TargetResolutionError
from reconforge.modules.port_scanning.models import (
    PortProbe,
    PortResult,
    PortState,
)


class StealthTransportProtocol(Protocol):
    def start_sniffer(self, callback: Callable[[int, PortState], None]) -> None: ...
    async def wait_ready(self) -> None: ...
    def send_packet(self, dport: int) -> None: ...
    def stop(self) -> None: ...


class StealthScanner:
    def __init__(self, transport: StealthTransportProtocol) -> None:
        self.transport = transport
        self.pending: dict[int, asyncio.Future[PortState]] = {}
        self.loop = asyncio.get_running_loop()

    def resolve(self, port: int, state: PortState) -> None:
        if port in self.pending and not self.pending[port].done():
            self.pending[port].set_result(state)

    def _sniffer_callback(self, port: int, state: PortState) -> None:
        self.loop.call_soon_threadsafe(self.resolve, port, state)

    async def scan_port(self, target: str, port: int, timeout: float) -> PortResult:
        future = self.loop.create_future()
        self.pending[port] = future

        try:
            self.transport.send_packet(port)
            state = await asyncio.wait_for(future, timeout=timeout)
            return PortResult(port=port, state=state)
        except TimeoutError:
            # Under RFC 793, an open or filtered port does not respond to FIN/NULL/XMAS.
            return PortResult(port=port, state=PortState.OPEN_FILTERED)
        finally:
            self.pending.pop(port, None)


@asynccontextmanager
async def _stealth_session(target: str, flags: str) -> AsyncIterator[PortProbe]:
    from reconforge.modules.port_scanning.stealth_transport import StealthTransport

    if os.geteuid() != 0:
        raise InsufficientPrivilegesError("Stealth scans require root privileges (or CAP_NET_RAW).")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as error:
        raise TargetResolutionError(f"Cannot resolve target {target!r}") from error

    transport = StealthTransport(target_ip, flags=flags)
    scanner = StealthScanner(transport)

    transport.start_sniffer(scanner._sniffer_callback)
    await transport.wait_ready()

    try:
        yield scanner.scan_port
    finally:
        transport.stop()


@asynccontextmanager
async def fin_session(target: str) -> AsyncIterator[PortProbe]:
    async with _stealth_session(target, flags="F") as probe:
        yield probe


@asynccontextmanager
async def null_session(target: str) -> AsyncIterator[PortProbe]:
    async with _stealth_session(target, flags="") as probe:
        yield probe


@asynccontextmanager
async def xmas_session(target: str) -> AsyncIterator[PortProbe]:
    async with _stealth_session(target, flags="FPU") as probe:
        yield probe
