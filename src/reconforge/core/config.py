from pathlib import Path

from .enums import Modules
from .models import Target


class Config:
    def __init__(
        self,
        target: str,
        modules: list[Modules],
        ports: list[str] | None,
        wordlist: Path | None,
        output: Path | None,
    ):
        self.target = Target(target)
        self.modules = [Modules(module) for module in modules]
        self.ports = ports if ports is not None else []
        self.wordlist = Path(wordlist) if wordlist else None
        self.output = Path(output) if output else None
