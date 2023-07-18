from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from data_models.shared import SiemEvent
from ..exec_data.verification_result import VerificationModuleClassResult, VerificationOverallResult


@dataclass
class CachedVerificationData:
    event: SiemEvent
    cvss: list[float]
    start: datetime = field(default_factory=datetime.now)
    end: Optional[datetime] = None
    total_count: int = 0
    verification_success: Optional[bool] = None
    verification_details: Optional[str] = None
    plaus_result: Optional[VerificationModuleClassResult] = None
    scanner_result: Optional[VerificationModuleClassResult] = None
    exploit_result: Optional[VerificationModuleClassResult] = None
    overall_result: Optional[VerificationOverallResult] = None

    def __post_init__(self):
        if self.event and isinstance(self.event, dict):
            self.event = SiemEvent(**self.event)
        if self.plaus_result and isinstance(self.plaus_result, dict):
            self.plaus_result = VerificationModuleClassResult(**self.plaus_result)
        if self.scanner_result and isinstance(self.scanner_result, dict):
            self.scanner_result = VerificationModuleClassResult(**self.scanner_result)
        if self.exploit_result and isinstance(self.exploit_result, dict):
            self.exploit_result = VerificationModuleClassResult(**self.exploit_result)
        if self.overall_result and isinstance(self.overall_result, dict):
            self.overall_result = VerificationOverallResult(**self.overall_result)
        if self.scanner_result and self.exploit_result and self.plaus_result:
            self.total_count = self.scanner_result.count + self.exploit_result.count + self.plaus_result.count
