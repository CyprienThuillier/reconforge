import asyncio
import socket
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Protocol

from reconforge.core.exceptions import InsufficientPrivilegesError, TargetResolutionError
from reconforge.modules.port_scanning.models import PortProbe, PortResult, PortState


class SynTransportProtocol(Protocol):
    def start_sniffer(self, callback: Callable[[int, PortState], None]) -> None: ...
    async def wait_ready(self) -> None: ...
    def send_syn(self, dport: int) -> None: ...
    def stop(self) -> None: ...


class SynScanner:
    def __init__(self, transport: SynTransportProtocol) -> None:
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
            self.transport.send_syn(port)
            state = await asyncio.wait_for(future, timeout=timeout)
            return PortResult(port=port, state=state)
        except TimeoutError:
            return PortResult(port=port, state=PortState.FILTERED)
        finally:
            self.pending.pop(port, None)


@asynccontextmanager
async def syn_session(target: str) -> AsyncIterator[PortProbe]:
    import os

    from reconforge.modules.port_scanning.syn_transport import SynTransport

    if os.geteuid() != 0:
        raise InsufficientPrivilegesError("SYN scan requires root privileges (or CAP_NET_RAW).")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as error:
        raise TargetResolutionError(f"Cannot resolve target {target!r}") from error

    transport = SynTransport(target_ip)
    scanner = SynScanner(transport)

    transport.start_sniffer(scanner._sniffer_callback)
    await transport.wait_ready()

    try:
        yield scanner.scan_port
    finally:
        transport.stop()
