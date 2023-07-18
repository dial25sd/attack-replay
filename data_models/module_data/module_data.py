from dataclasses import dataclass
from typing import Optional, Union

from arf_io.exceptions import ModuleDefinitionError
from arf_io.ui import ArfLogger
from utils import ArfEnum
from .module_categories import ModuleClass, ModuleType
from .module_data_param import ModuleParam
from .module_data_result import ModuleResultCriterion
from .module_data_success import ModuleSuccessCriterion, ModuleSuccessStrategy


class MsfModuleExecMode(ArfEnum):
    RUN = "run"
    CHECK = "check"


@dataclass
class ModuleData:
    name: str
    module_class: Union[str, ModuleClass]
    module_type: Union[str, ModuleType]
    parameters: list[ModuleParam]
    path: Optional[str] = None
    exec_mode: Optional[MsfModuleExecMode] = None  # only relevant for MSF modules
    source: Optional[str] = None
    payload_parameters: Optional[list[ModuleParam]] = None
    success: Optional[list[ModuleSuccessCriterion]] = None
    result: Optional[ModuleResultCriterion] = None  # only relevant for param_scanner modules

    def __post_init__(self):
        try:
            self.module_class = ModuleClass(self.module_class)
            self.module_type = ModuleType(self.module_type)
            self.exec_mode = MsfModuleExecMode(self.exec_mode) if self.exec_mode else None
            self.parameters = [ModuleParam(**param) for param in self.parameters] if self.parameters else []
            self.payload_parameters = [ModuleParam(**p) for p in
                                       self.payload_parameters] if self.payload_parameters else []
            self.success = [ModuleSuccessCriterion(**c) for c in self.success] if self.success else []
            self.source = f"Metasploit Framework: {self.path}" if self.module_type is ModuleType.MSF else self.source
            self.result = ModuleResultCriterion(**self.result) if self.result else None
        except Exception as e:
            raise ModuleDefinitionError(e)

    def __str__(self) -> str:
        param_len = len(self.parameters) if self.parameters else 0
        payload_param_len = len(self.payload_parameters) if self.payload_parameters else 0
        success_criteria_len = len(self.success) if self.success else 0
        return f"ModuleData(name: {self.name}, class: {self.module_class}, type: {self.module_type}, # params: {payload_param_len}, # payload_params: {payload_param_len}, # success_criteria: {success_criteria_len})"

    def validate(self) -> None:
        logger = ArfLogger.instance()
        if self.path is None and self.module_type is ModuleType.MSF:
            raise ModuleDefinitionError(f"Module is of type MSF, but 'path' is missing.")
        if self.name is None or self.module_class is None or self.module_type is None:
            raise ModuleDefinitionError(f"Failed to validate required field for module {self.name}.")
        if self.module_type is ModuleType.STANDALONE and self.exec_mode is not None:
            logger.warn(f"Exec mode set for standalone module {self.name}: will be ignored.")
        if self.module_class is ModuleClass.EXPLOIT and self.module_type is ModuleType.MSF and self.exec_mode is MsfModuleExecMode.CHECK:
            raise ModuleDefinitionError(f"MSF modules of ModuleType 'EXPLOIT' cannot be run in 'check' mode.")
        if self.module_type is ModuleType.STANDALONE and self.success:
            for criterion in self.success:
                if criterion.strategy is ModuleSuccessStrategy.SESSION:
                    raise ModuleDefinitionError(f"Standalone modules can't make use of 'session' success strategy.")
        for param in self.parameters:
            param.validate()
