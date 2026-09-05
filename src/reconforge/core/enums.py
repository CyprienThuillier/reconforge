from enum import Enum


class ScanType(str, Enum):
    SYN = "syn"
    TCP = "tcp"
    CONNECT = "connect"
    UDP = "udp"
    FIN = "fin"


class EnumType(str, Enum):
    SUBDOMAIN = "subdomain"
    FOLDERS = "folders"
