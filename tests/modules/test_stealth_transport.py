from unittest.mock import MagicMock

import pytest
from scapy.all import IP, TCP  # type: ignore[attr-defined]

from reconforge.modules.port_scanning.models import PortState
from reconforge.modules.port_scanning.stealth_transport import StealthTransport


def test_transport_initialization() -> None:
    transport_fin = StealthTransport("10.0.0.5", flags="F")
    assert transport_fin.base_pkt.dst == "10.0.0.5"
    assert transport_fin.flags == "F"

    transport_null = StealthTransport("10.0.0.5", flags="")
    assert transport_null.flags == ""

    transport_xmas = StealthTransport("10.0.0.5", flags="FPU")
    assert transport_xmas.flags == "FPU"


def test_transport_handle_packet_detects_rst() -> None:
    transport = StealthTransport("10.0.0.5", flags="F")
    callback = MagicMock()
    transport.callback = callback

    # Packet with RST flag (0x04)
    rst_pkt = IP(src="10.0.0.5") / TCP(sport=80, dport=54321, flags="R")
    transport._handle_packet(rst_pkt)

    callback.assert_called_once_with(80, PortState.CLOSED)


def test_transport_handle_packet_ignores_non_rst() -> None:
    transport = StealthTransport("10.0.0.5", flags="F")
    callback = MagicMock()
    transport.callback = callback

    # Packet with ACK only (no RST)
    ack_pkt = IP(src="10.0.0.5") / TCP(sport=80, dport=54321, flags="A")
    transport._handle_packet(ack_pkt)

    callback.assert_not_called()


def test_transport_send_packet_without_sniffer_raises() -> None:
    transport = StealthTransport("10.0.0.5", flags="F")
    with pytest.raises(RuntimeError, match="Sniffer must be started"):
        transport.send_packet(80)
