# tests/modules/test_registry.py
import pytest

from reconforge.core.enums import ScanType
from reconforge.core.exceptions import UnsupportedScanTypeError
from reconforge.modules.port_scanning import connect_session, get_session


def test_get_session_returns_connect_session() -> None:
    assert get_session(ScanType.CONNECT) is connect_session


def test_get_session_rejects_unimplemented_scan_type() -> None:
    with pytest.raises(UnsupportedScanTypeError):
        get_session(ScanType.UDP)


def test_unsupported_scan_type_error_message_contains_scan_type() -> None:
    with pytest.raises(UnsupportedScanTypeError, match="udp"):
        get_session(ScanType.UDP)
