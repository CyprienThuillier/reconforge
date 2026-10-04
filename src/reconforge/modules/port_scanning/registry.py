from reconforge.core.enums import ScanType
from reconforge.core.exceptions import UnsupportedScanTypeError
from reconforge.modules.port_scanning.connect import scan_port_connect
from reconforge.modules.port_scanning.models import PortProbe

SCANNERS: dict[ScanType, PortProbe] = {
    ScanType.CONNECT: scan_port_connect,
}


def get_probe(scan_type: ScanType) -> PortProbe:
    if scan_type not in SCANNERS:
        raise UnsupportedScanTypeError(f"Scan type {scan_type.value!r} is not implemented yet")
    return SCANNERS[scan_type]
