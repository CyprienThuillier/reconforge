import asyncio
import socket
import threading
from collections.abc import Callable

from scapy.all import IP, TCP, AsyncSniffer, conf, raw  # type: ignore[attr-defined]

from reconforge.modules.port_scanning.models import PortState


class SynTransport:
    def __init__(self, target_ip: str) -> None:
        self.target_ip = target_ip
        self.source_port = 54321
        self.seq = 1000
        self.ready_event = threading.Event()
        self.callback: Callable[[int, PortState], None] | None = None
        self.sock: socket.socket | None = None  # ouvert dans start_sniffer (nécessite root)

        self.base_pkt = IP(dst=self.target_ip) / TCP(
            sport=self.source_port, seq=self.seq, flags="S"
        )

        self.sniffer = AsyncSniffer(
            filter=f"tcp and src host {self.target_ip} and dst port {self.source_port}",
            prn=self._handle_packet,
            started_callback=self.ready_event.set,
            store=False,
            iface=conf.loopback_name if self.target_ip.startswith("127.") else None,
        )

    def _handle_packet(self, pkt: IP) -> None:
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            if tcp.ack == self.seq + 1:
                if tcp.flags & 0x12 == 0x12 and self.callback:  # SYN-ACK
                    self.callback(tcp.sport, PortState.OPEN)
                elif tcp.flags & 0x04 == 0x04 and self.callback:  # RST
                    self.callback(tcp.sport, PortState.CLOSED)

    def start_sniffer(self, callback: Callable[[int, PortState], None]) -> None:
        self.callback = callback
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.sniffer.start()

    async def wait_ready(self) -> None:
        while not self.ready_event.is_set():
            await asyncio.sleep(0.01)

    def send_syn(self, dport: int) -> None:
        if self.sock is None:
            raise RuntimeError("Sniffer must be started before sending packets")
        pkt = self.base_pkt.copy()
        pkt[TCP].dport = dport
        self.sock.sendto(raw(pkt), (self.target_ip, 0))

    def stop(self) -> None:
        self.sniffer.stop()
        self.sniffer.join()
        if self.sock is not None:
            self.sock.close()
