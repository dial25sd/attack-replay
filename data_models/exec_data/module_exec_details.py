from dataclasses import dataclass, field
from typing import Any, Optional

from data_models.module_data import ModuleSuccessCriterion


@dataclass
class MsfSession:
    id: int
    session: dict = field(default_factory=dict)


@dataclass
class ModuleExecDetails:
    module_name: Optional[str] = None
    module_source: Optional[str] = None
    output: Optional[str] = None
    params: dict[str, str] = field(default_factory=dict)
    module_success: Optional[bool] = None  # has this module fulfilled its purpose?
    module_exec_success: Optional[bool] = None  # has this module been technically executed successfully?
    session: Optional[Any] = None
    gathered_info: dict[str, str] = field(default_factory=dict)
    exit_code: Optional[int] = None
    matching_success_criterion: Optional[ModuleSuccessCriterion] = None

    def __post_init__(self):
        self.matching_success_criterion = ModuleSuccessCriterion(
            **self.matching_success_criterion) if self.matching_success_criterion is not None and isinstance(
            self.matching_success_criterion, dict) else self.matching_success_criterion

    def __str__(self):
        return f"ModuleExecDetails(name={self.module_name}, success={self.module_success}, exec_success={self.module_exec_success}, session={self.session}, exit_code={self.exit_code}, matching_success_criterion={self.matching_success_criterion})"
