from enum import Enum


class ScanType(str, Enum):
    SYN = "syn"
    CONNECT = "connect"
    UDP = "udp"
    FIN = "fin"


class EnumType(str, Enum):
    SUBDOMAIN = "subdomain"
    DIRECTORIES = "directories"
