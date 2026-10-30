from collections.abc import Callable

from reconforge.core.enums import ScanType
from reconforge.core.exceptions import UnsupportedScanTypeError
from reconforge.modules.port_scanning.connect import connect_session
from reconforge.modules.port_scanning.models import ScanSession
from reconforge.modules.port_scanning.stealth import (
    fin_session,
    null_session,
    xmas_session,
)
from reconforge.modules.port_scanning.syn import syn_session

SESSIONS: dict[ScanType, Callable[[str], ScanSession]] = {
    ScanType.CONNECT: connect_session,
    ScanType.SYN: syn_session,
    ScanType.FIN: fin_session,
    ScanType.NULL: null_session,
    ScanType.XMAS: xmas_session,
}


def get_session(scan_type: ScanType) -> Callable[[str], ScanSession]:
    if scan_type not in SESSIONS:
        raise UnsupportedScanTypeError(f"Scan type {scan_type.value!r} is not implemented yet")
    return SESSIONS[scan_type]
