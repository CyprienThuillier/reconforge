from reconforge.core.enums import Modules



def test_modules_enum_values():
    assert Modules.PORT_SCAN.value == "ports"
    assert Modules.SUBDOMAIN_ENUM.value == "subdomains"
