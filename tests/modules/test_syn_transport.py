from reconforge.modules.port_scanning.syn_transport import SynTransport


def test_transport_uses_given_target_ip() -> None:
    transport = SynTransport("10.0.0.5")

    assert transport.base_pkt.dst == "10.0.0.5"
