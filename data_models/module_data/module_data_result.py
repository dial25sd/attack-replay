from dataclasses import dataclass
from typing import Union

from utils import ArfEnum


class ModuleResultStrategy(ArfEnum):  # only relevant for param_scanner modules
    EXTRACT = "extract"  # extract the result from the module's output
    SUCCESS = "success"  # apply the success criteria and take this as result; when arguments are given: first one is taken in case of success, second is default


@dataclass
class ModuleResultCriterion:
    strategy: ModuleResultStrategy
    argument: Union[str, list[str]]

    def __post_init__(self):
        self.strategy = ModuleResultStrategy(self.strategy)

    def __str__(self) -> str:
        return f"ModuleResultCriterion({self.strategy}('{self.argument}'))"
