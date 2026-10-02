# tests/modules/test_registry.py
import pytest

from reconforge.core.enums import ScanType
from reconforge.core.exceptions import UnsupportedScanTypeError
from reconforge.modules.port_scanning import get_probe, scan_port_connect


def test_get_probe_returns_connect_probe() -> None:
    assert get_probe(ScanType.CONNECT) is scan_port_connect


def test_get_probe_rejects_unimplemented_scan_type() -> None:
    with pytest.raises(UnsupportedScanTypeError):
        get_probe(ScanType.UDP)


def test_unsupported_scan_type_error_message_contains_scan_type() -> None:
    with pytest.raises(UnsupportedScanTypeError, match="udp"):
        get_probe(ScanType.UDP)
