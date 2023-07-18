from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from data_models.report.report_entry import ReportEntry


@dataclass
class ArfExecStats:
    start: datetime
    args: dict
    end: Optional[datetime] = None
    successfully_verified_events: int = 0
    total_successful_module_count: int = 0
    total_successful_plaus_count: int = 0
    total_successful_scanner_count: int = 0
    total_successful_exploit_count: int = 0
    verification_data: list[ReportEntry] = field(default_factory=list)
