from collections.abc import Callable

from reconforge.modules.port_scanning.models import PortState


class SynTransport:
    def start_sniffer(self, callback: Callable[[int, PortState], None]) -> None:
        pass

    async def wait_ready(self) -> None:
        pass

    def send_syn(self, dport: int) -> None:
        pass

    def stop(self) -> None:
        pass
