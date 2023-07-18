from dataclasses import dataclass

from ..module_data import ModuleData, ModuleParam, ModuleResultCriterion, ModuleSuccessCriterion


@dataclass
class ModuleExecData:
    module_data: ModuleData
    overridden_params: list[ModuleParam]
    overridden_payload_params: list[ModuleParam]
    overridden_success: list[ModuleSuccessCriterion]
    overridden_result: ModuleResultCriterion

    def __post_init__(self):
        self.overridden_params = [ModuleParam(**p) if isinstance(p, dict) else p for p in
                                  self.overridden_params] if self.overridden_params else []
        self.overridden_payload_params = [ModuleParam(**p) if isinstance(p, dict) else p for p in
                                          self.overridden_payload_params] if self.overridden_payload_params else []
        self.overridden_success = [ModuleSuccessCriterion(**c) if isinstance(c, dict) else c for c in
                                   self.overridden_success] if self.overridden_success else []
        self.overridden_result = ModuleResultCriterion(**self.overridden_result) if isinstance(self.overridden_result,
            dict) else self.overridden_result
