from pathlib import Path

from reconforge.core.validators import 
    validate_port, 
    validate_target, 
    validate_wordlist,
    validate_output,


class ScanConfig:
    def __init__(
        self,
        target: str,
        ports: list[int] | None = None,
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

    @classmethod
    def port_scan(
        cls,
        target: str,
        ports: str | None = None,
        scan_type: str | None = None,
        mode: str | None = None,
        wordlist: Path | None = None,
        verbose: bool = False,
        output: Path | None = None,
    ) -> "ScanConfig":

        validate_target(target)

        parsed_ports: list[int] | None = None
        if ports is not None:
            validate_port(ports)
            parsed_ports = parse_ports(ports)

        ouput_path: Path | None = None
        if output is not None:
            validate_output(output)
            ouput_path = output

        return cls(
            target=target,
            ports=parsed_ports,
            scan_type=scan_type,
            mode=mode,
            wordlist=wordlist,
            verbose=verbose,
            output=output,
        )

    @classmethod
    def enum(
        cls,
        target: str,
        ports: str | None = None,
        scan_type: str | None = None,
        mode: str | None = None,
        wordlist: Path | None = None,
        verbose: bool = False,
        output: Path | None = None,
    ) -> "ScanConfig":

        validate_target(target)

        wordlist_path: Path | None = None
        if wordlist is not None:
            validate_wordlist(wordlist)
            wordlist_path = wordlist
            
        ouput_path: Path | None = None
        if output is not None:
            validate_output(output)
            ouput_path = output

        return cls(
            target=target,
            ports=ports,
            scan_type=scan_type,
            mode=mode,
            wordlist=wordlist_path,
            verbose=verbose,
            output=output,
        )


def parse_ports(ports: str) -> list[int]:
    if "-" in ports:
        start_str, end_str = ports.split("-")
        return list(range(int(start_str), int(end_str) + 1))
    if "," in ports:
        return [int(port) for port in ports.split(",")]
    return [int(ports)]
