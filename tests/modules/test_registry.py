# tests/modules/test_registry.py
import pytest

from reconforge.core.enums import ScanType
from reconforge.core.exceptions import UnsupportedScanTypeError
from reconforge.modules.port_scanning import (
    connect_session,
    fin_session,
    get_session,
    null_session,
    syn_session,
    xmas_session,
)


def test_get_session_returns_registered_sessions() -> None:
    assert get_session(ScanType.CONNECT) is connect_session
    assert get_session(ScanType.SYN) is syn_session
    assert get_session(ScanType.FIN) is fin_session
    assert get_session(ScanType.NULL) is null_session
    assert get_session(ScanType.XMAS) is xmas_session


def test_get_session_rejects_unimplemented_scan_type() -> None:
    with pytest.raises(UnsupportedScanTypeError):
        get_session(ScanType.UDP)


def test_unsupported_scan_type_error_message_contains_scan_type() -> None:
    with pytest.raises(UnsupportedScanTypeError, match="udp"):
        get_session(ScanType.UDP)
