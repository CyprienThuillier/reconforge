from reconforge.core.enums import EnumType, ScanType


def test_scan_type_values():
    assert ScanType.SYN.value == "syn"
    assert ScanType.TCP.value == "tcp"
    assert ScanType.CONNECT.value == "connect"
    assert ScanType.UDP.value == "udp"
    assert ScanType.FIN.value == "fin"


def test_scan_type_is_str_enum():
    assert ScanType.SYN == "syn"
    assert isinstance(ScanType.SYN, str)


def test_scan_type_from_value():
    assert ScanType("syn") is ScanType.SYN
    assert ScanType("udp") is ScanType.UDP


def test_scan_type_invalid_value_raises():
    import pytest

    with pytest.raises(ValueError):
        ScanType("invalid")


def test_enum_type_values():
    assert EnumType.SUBDOMAIN.value == "subdomain"
    assert EnumType.FOLDERS.value == "folders"


def test_enum_type_is_str_enum():
    assert EnumType.SUBDOMAIN == "subdomain"
    assert isinstance(EnumType.FOLDERS, str)


def test_enum_type_from_value():
    assert EnumType("subdomain") is EnumType.SUBDOMAIN
    assert EnumType("folders") is EnumType.FOLDERS


def test_enum_type_invalid_value_raises():
    import pytest

    with pytest.raises(ValueError):
        EnumType("invalid")
