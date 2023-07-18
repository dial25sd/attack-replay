from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from data_models.exec_data.module_exec_details import ModuleExecDetails
from data_models.exec_data.verification_result import ModuleAggregatedSuccess
from data_models.shared import SiemEvent
from .report_cache_data import CachedVerificationData


@dataclass
class ReportEntry:
    start_time: datetime
    end_time: datetime
    event_id: str
    verified_host: str
    verified_port: int
    verified_cves: list[str] = field(default_factory=list)
    cvss_score: list[float] = field(default_factory=list)
    verified_event: Optional[SiemEvent] = None
    verification_success: Optional[bool] = None
    verification_details: Optional[str] = None
    overall_result: Optional[str] = None
    result_confidence: Optional[float] = None
    host_state: Optional[str] = None
    module_count: Optional[int] = None
    plausibility_count: Optional[int] = None
    plausibility_details: Optional[str] = None
    plausibility_result: Optional[str] = None
    scanner_count: Optional[int] = None
    scanner_success: list[str] = field(default_factory=list)
    scanner_error: list[str] = field(default_factory=list)
    scanner_details: Optional[str] = None
    scanner_result: Optional[str] = None
    exploit_count: Optional[int] = None
    exploit_success: list[str] = field(default_factory=list)
    exploit_error: list[str] = field(default_factory=list)
    exploit_details: Optional[str] = None
    exploit_result: Optional[str] = None

    @staticmethod
    def incorporate_cached_data(cached: CachedVerificationData):
        e = ReportEntry(verified_event=cached.event, event_id=str(cached.event.id), start_time=cached.start,
                        end_time=cached.end, verified_host=str(cached.event.dst.ip),
                        verified_port=cached.event.dst.port, verified_cves=cached.event.cves, cvss_score=cached.cvss,
                        verification_details=cached.verification_details)
        if cached.plaus_result:
            e.plausibility_count = cached.plaus_result.count
            e.plausibility_details = ReportEntry.__get_details_str_for_all(cached.plaus_result.details)
            e.plausibility_result = cached.overall_result.plausibility.name
        if cached.scanner_result:
            e.scanner_success = cached.scanner_result.successful_modules
            e.scanner_error = cached.scanner_result.erroneous_modules
            e.scanner_result = ReportEntry.__get_result(cached.scanner_result.result, ModuleAggregatedSuccess.NONE,
                                                        "Not vulnerable", "VULNERABLE")
            e.scanner_count = cached.scanner_result.count
            e.scanner_details = ReportEntry.__get_details_str_for_all(cached.scanner_result.details)
        if cached.exploit_result:
            e.exploit_success = cached.exploit_result.successful_modules
            e.exploit_error = cached.exploit_result.erroneous_modules
            e.exploit_result = ReportEntry.__get_result(cached.exploit_result.result, ModuleAggregatedSuccess.NONE,
                                                        "Not Exploitable", "EXPLOITABLE")
            e.exploit_count = cached.exploit_result.count
            e.exploit_details = ReportEntry.__get_details_str_for_all(cached.exploit_result.details)
        if cached.overall_result:
            e.overall_result = str(cached.overall_result.vuln_state)
            e.result_confidence = str(cached.overall_result.confidence)
            e.host_state = str(cached.overall_result.host_state)
        e.module_count = cached.total_count
        e.verification_success = cached.verification_success
        return e

    @staticmethod
    def __get_result(result: ModuleAggregatedSuccess, conditional_result: ModuleAggregatedSuccess, success_name: str,
                     failure_name: str) -> str:
        if result is None:
            return "N/A"
        if result == conditional_result.value:
            return success_name
        else:
            return failure_name

    @staticmethod
    def __get_details_str_for_all(details: list[ModuleExecDetails]) -> str:
        return '\n'.join(ReportEntry.__get_details_str(detail) for detail in details) if details else ""

    @staticmethod
    def __get_details_str(details: ModuleExecDetails) -> str:
        details_str = f"Module: {details.module_name}\nSource: {details.module_source} \nParams: {details.params}\nExit Code: {details.exit_code}\n"
        if details.matching_success_criterion:
            details_str = f"{details_str}Matching Success Criterion: {details.matching_success_criterion.strategy}({details.matching_success_criterion.argument})\n"
        if details.session:
            details_str = f"{details_str}Session: {details.session} \nGathered Info: {details.gathered_info} \n"
        details_str = f"{details_str}Output: '{details.output}' \n"
        return details_str
