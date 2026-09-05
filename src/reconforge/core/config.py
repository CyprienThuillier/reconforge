from pathlib import Path

# from .enums import EnumType, ScanType


class ScanConfig:
    def __init__(
        self,
        target: str,
        ports: str | None = None,
        scan_type: str | None = None,
        mode: str | None = None,
        wordlist: Path | None = None,
        verbose: bool = False,
        output: Path | None = None,
    ):

        self.target = target
        self.ports = ports
        self.scan_type = scan_type
        self.mode = mode
        self.wordlist = wordlist
        self.output = output
        self.verbose = verbose
