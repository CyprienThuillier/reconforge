from collections.abc import Callable

from reconforge.core.enums import ScanType
from reconforge.core.exceptions import UnsupportedScanTypeError
from reconforge.modules.port_scanning.connect import connect_session
from reconforge.modules.port_scanning.models import ScanSession

SESSIONS: dict[ScanType, Callable[[], ScanSession]] = {
    ScanType.CONNECT: connect_session,
}


def get_session(scan_type: ScanType) -> Callable[[], ScanSession]:
    if scan_type not in SESSIONS:
        raise UnsupportedScanTypeError(f"Scan type {scan_type.value!r} is not implemented yet")
    return SESSIONS[scan_type]
