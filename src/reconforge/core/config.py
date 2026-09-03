from .models import Target
from .enums import Modules

from pathlib import Path

class Config():
    def __init__(self, target:str, modules:list[Modules], ports:list[str] | [], wordlist:Path | None, output:Path) # set a default path for output
        self.target = Target(target)
        self.modules = [Modules(module) for module in modules]
        self.ports = ports
        self.wordlist = wordlist
        self.output = output
