from dataclasses import dataclass
from typing import Optional

from utils import ArfEnum
from .module_exec_details import ModuleExecDetails
from .vulnerability_result import Confidence, Plausibility, VulnerabilityState


class HostStateAfterVerification(ArfEnum):
    NOT_COMPARABLE = 1
    UNCHANGED = 2
    CHANGED = 3


class ModuleAggregatedSuccess(ArfEnum):
    NONE = 1  # no module was successful
    MIXED = 2  # one of at least two modules has been successful
    ALL = 3  # all modules have been successful


@dataclass
class VerificationOverallResult:
    plausibility: Plausibility
    vuln_state: VulnerabilityState
    confidence: Confidence
    host_state: HostStateAfterVerification

    def __post_init__(self):
        self.plausibility = Plausibility(self.plausibility) if self.plausibility else None
        self.vuln_state = VulnerabilityState(self.vuln_state) if self.vuln_state else None
        self.confidence = Confidence(self.confidence) if self.confidence else None
        self.host_state = HostStateAfterVerification(self.host_state) if self.host_state else None

    def __str__(self) -> str:
        return f"vuln={self.vuln_state}, plaus={self.plausibility}, confidence={self.confidence}, host_state={self.host_state}"


# represents the results of one class of modules, e.g. the 'exploit result'
@dataclass
class VerificationModuleClassResult:
    successful_modules: list[str]
    erroneous_modules: list[str]
    result: Optional[ModuleAggregatedSuccess]
    details: list[ModuleExecDetails]
    count: int = -1

    def __post_init__(self):
        self.count = len(self.successful_modules) + len(self.erroneous_modules)
        if self.details:
            self.details = [ModuleExecDetails(**d) if isinstance(d, dict) else d for d in self.details]


@dataclass
class VerificationModuleResults:
    plausibility: VerificationModuleClassResult
    scanner: VerificationModuleClassResult
    exploit: VerificationModuleClassResult
    post_verification_plaus: VerificationModuleClassResult
