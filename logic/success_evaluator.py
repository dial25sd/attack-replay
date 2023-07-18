from arf_io.ui import ArfLogger
from data_models.exec_data import Confidence, HostStateAfterVerification, ModuleAggregatedSuccess, Plausibility, \
    VerificationModuleClassResult, VerificationModuleResults, VulnerabilityState
from data_models.report import CachedVerificationData


class SuccessEvaluator:

    def __init__(self):
        self.logger = ArfLogger.instance()

    def get_overall_vulnerability_state(self, plausibility: Plausibility,
                                        result: VerificationModuleResults) -> VulnerabilityState:
        if plausibility == Plausibility.NOT_PLAUSIBLE or not self.__has_event_been_verified_successfully(result):
            res = VulnerabilityState.UNKNOWN
        elif result.exploit.result != ModuleAggregatedSuccess.NONE and len(result.exploit.successful_modules) > 0:
            res = VulnerabilityState.EXPLOITABLE
        elif result.scanner.result != ModuleAggregatedSuccess.NONE and len(result.scanner.successful_modules) > 0:
            res = VulnerabilityState.NOT_EXPLOITABLE
        elif len(result.scanner.successful_modules) > 0 or len(result.exploit.successful_modules) > 0:
            res = VulnerabilityState.NOT_VULNERABLE
        else:
            res = VulnerabilityState.UNKNOWN
        self.logger.debug(f"Determined module result as '{res}'.", 1)
        return res

    def get_plausibility(self, result: ModuleAggregatedSuccess) -> Plausibility:
        if result == ModuleAggregatedSuccess.ALL:
            plausibility = Plausibility.PLAUSIBLE
        elif result == ModuleAggregatedSuccess.NONE:
            plausibility = Plausibility.NOT_PLAUSIBLE
        else:
            plausibility = Plausibility.UNCERTAIN
        self.logger.debug(f"Determined plausibility given by {result} as '{plausibility}'.", 1)
        return plausibility

    def get_confidence(self, plausibility: Plausibility, vuln_state: VulnerabilityState) -> Confidence:
        conf = (
            None if vuln_state == VulnerabilityState.UNKNOWN else
            Confidence.HIGH if plausibility != Plausibility.NOT_PLAUSIBLE and vuln_state == VulnerabilityState.EXPLOITABLE or plausibility == Plausibility.NOT_PLAUSIBLE and vuln_state == VulnerabilityState.NOT_VULNERABLE else
            Confidence.LOW if plausibility == Plausibility.NOT_PLAUSIBLE and vuln_state != VulnerabilityState.NOT_VULNERABLE else
            Confidence.MEDIUM)
        self.logger.debug(f"Determined confidence for plausibility as '{conf}'.", 1)
        return conf

    def compare_host_state(self, plaus_res: VerificationModuleClassResult,
                           post_verification_plaus: VerificationModuleClassResult) -> HostStateAfterVerification:
        if plaus_res.successful_modules == post_verification_plaus.successful_modules and plaus_res.erroneous_modules == post_verification_plaus.erroneous_modules:
            if plaus_res.result == post_verification_plaus.result:
                self.logger.success(
                    "No change of state has been observed when executing the plaus checks after event verification")
                return HostStateAfterVerification.UNCHANGED
            else:
                self.logger.warn("Change of state has been observed on the host after having verified the event!")
                return HostStateAfterVerification.CHANGED
        else:
            self.logger.warn(
                "Can't compare results of plaus checks pre & post verification: difference in successfully executed modules")
            return HostStateAfterVerification.NOT_COMPARABLE

    @staticmethod
    def __has_event_been_verified_successfully(res: VerificationModuleResults) -> bool:
        return all(
            len(mod.erroneous_modules) == 0 if mod else True for mod in [res.plausibility, res.scanner, res.exploit])

    @staticmethod
    def get_exploitable_count(cached_verification_data: list[CachedVerificationData]) -> int:
        return len([x for x in cached_verification_data if
                    x.overall_result is not None and x.overall_result.vuln_state == VulnerabilityState.EXPLOITABLE])

    @staticmethod
    def get_vulnerable_count(cached_verification_data: list[CachedVerificationData]) -> int:
        return len([x for x in cached_verification_data if x.overall_result is not None and (
                x.overall_result.vuln_state == VulnerabilityState.EXPLOITABLE or x.overall_result.vuln_state == VulnerabilityState.NOT_EXPLOITABLE)])
