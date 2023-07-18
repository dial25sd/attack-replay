from dataclasses import dataclass
from typing import Optional

from utils import ArfEnum


class ModuleSuccessStrategy(ArfEnum):
    OUTPUT = "output"
    SESSION = "session"  # only works for MSF modules
    EXIT_CODE = "exit_code"
    FALLBACK = "fallback"


@dataclass
class ModuleSuccessCriterion:
    strategy: ModuleSuccessStrategy
    conclusion: bool
    argument: Optional[str] = None

    def __post_init__(self):
        self.strategy = ModuleSuccessStrategy(self.strategy)

    def __str__(self) -> str:
        return f"ModuleSuccessCriterion({self.strategy}('{self.argument}'))"
