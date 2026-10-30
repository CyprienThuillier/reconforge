from enum import Enum


class ScanType(str, Enum):
    SYN = "syn"
    CONNECT = "connect"
    UDP = "udp"
    FIN = "fin"
    NULL = "null"
    XMAS = "xmas"


class EnumType(str, Enum):
    SUBDOMAIN = "subdomain"
    DIRECTORIES = "directories"
