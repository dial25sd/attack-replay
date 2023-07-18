import datetime
from argparse import Namespace

from arf_io.db import DbHandler
from arf_io.exceptions import ExceptionHandler, ModuleDefinitionError
from arf_io.external_apis import CvssFetcher
from arf_io.interprocess import DockerHandler, MsfHandler
from arf_io.ui import ArfLogger
from data_models.exec_data import ModuleAggregatedSuccess, ModuleExecDetails, VerificationModuleClassResult, \
    VerificationModuleResults, VerificationOverallResult
from data_models.module_data import ModuleClass, ModuleWithParamOverrides, ModulesForVuln
from data_models.report import CachedVerificationData
from data_models.shared import SiemEvent
from utils import IPNetwork, TimeUtils
from .module_executor import ModuleExecutor
from .module_repo_cache import ModuleRepoCache
from .success_evaluator import SuccessEvaluator


class EventProcessor:

    def __init__(self, module_repo_cache: ModuleRepoCache, internal_subnets: list[IPNetwork], timeout: int,
                 msf_handler: MsfHandler, docker_handler: DockerHandler, db: DbHandler, verification_threshold: int):
        self.logger = ArfLogger.instance()
        self.module_repo_cache = module_repo_cache
        self.module_executor = ModuleExecutor(module_repo_cache, internal_subnets, msf_handler=msf_handler,
                                              docker_handler=docker_handler, timeout=timeout)
        self.db = db
        self.cvss_fetcher = CvssFetcher(db=db)
        self.success_evaluator = SuccessEvaluator()
        self.verification_threshold = verification_threshold
        self.exception_handler = ExceptionHandler()

    def process_all_events(self, events: list[SiemEvent], arf_args: Namespace) -> None:
        for event in events:
            self.logger.increment_event_no()
            try:
                result = self.process_single_event(event=event, arf_args=arf_args)
                self.logger.warn(f"Verification result: {result}")
            except Exception as e:
                err_msg = f"Critical error during processing event {event.id}. Skipping."
                self.exception_handler.handle(e, msg=err_msg, reraise=False)

    def process_single_event(self, event: SiemEvent, arf_args: Namespace) -> VerificationOverallResult:
        self.logger.print_centered_hollow(f"Event: {event.id}")
        self.logger.info(f"Processing event {event.id} with CVEs '{','.join(event.cves)}'...")
        module_res, overall_res, verification_details = None, None, None
        if not event.cves or not any(x is not None for x in event.cves):
            verification_details = "Event has NOT been verified due to missing CVE IDs"
            self.logger.warn(verification_details)
        else:
            cvss = [cvss.score for cvss in self.cvss_fetcher.get_many_cvss_scores(event.cves) if cvss is not None]
            self.db.write_verification_data(CachedVerificationData(event=event, cvss=cvss))
            if not self.__has_recently_been_verified(event_id=event.id, host=event.dst, cves=event.cves):
                try:
                    modules_for_vuln = self.module_repo_cache.get_modules_for_vuln(cves=event.cves)
                    module_res = self.__find_exec_all_modules(arf_args, event, modules_for_vuln)
                    plausibility = self.success_evaluator.get_plausibility(module_res.plausibility.result)
                    vuln_state = self.success_evaluator.get_overall_vulnerability_state(plausibility, module_res)
                    confidence = self.success_evaluator.get_confidence(plausibility=plausibility, vuln_state=vuln_state)
                    host_state = self.success_evaluator.compare_host_state(module_res.plausibility,
                                                                           module_res.post_verification_plaus)

                    overall_res = VerificationOverallResult(plausibility=plausibility, vuln_state=vuln_state,
                                                            confidence=confidence, host_state=host_state)

                    verification_details = "Event has been verified."
                    self.logger.info(verification_details)
                except ModuleDefinitionError as e:
                    verification_details = f"Event has NOT been verified, due to missing vuln metadata file. See docs."
                    self.exception_handler.handle(e, reraise=True)
                except Exception as e:
                    verification_details = f"Event has NOT been verified, due to an error: {e}"
                    self.exception_handler.handle(e, reraise=True)
                finally:
                    self.db.conclude_verification_data(event.id, module_res=module_res, overall_res=overall_res,
                                                       verification_details=verification_details)
            else:
                verification_details = "Event has NOT been verified due to the host having been verified recently"
        self.db.conclude_verification_data(event.id, module_res=module_res, overall_res=overall_res,
                                           verification_details=verification_details)
        return overall_res

    def __find_exec_all_modules(self, arf_args: Namespace, event: SiemEvent,
                                modules_for_vuln: list[ModulesForVuln]) -> VerificationModuleResults:
        modules = self.__filter_modules_for_vuln(modules_for_vuln, cves=event.cves if event.cves else None)
        plaus_res = self.__exec_modules_of_class(arf_args, event, ModuleClass.PLAUSIBILITY,
                                                 modules=modules.plausibility, title="PLAUSIBILITY CHECKS")
        if plaus_res.result == ModuleAggregatedSuccess.NONE:
            self.logger.warn("All plausibility checks have returned a negative result, no further investigation needed")
            scanner_res = VerificationModuleClassResult([], [], None, [])
            exploit_res = VerificationModuleClassResult([], [], None, [])
            post_verification_plaus = VerificationModuleClassResult([], [], None, [])
        else:
            scanner_res = self.__exec_modules_of_class(arf_args, event, module_class=ModuleClass.SCANNER,
                                                       modules=modules.scanners, title="SCANNERS")
            exploit_res = self.__exec_modules_of_class(arf_args, event, module_class=ModuleClass.EXPLOIT,
                                                       modules=modules.exploits, title="EXPLOITS")
            post_verification_plaus = self.__exec_modules_of_class(arf_args, event,
                                                                   module_class=ModuleClass.PLAUSIBILITY,
                                                                   modules=modules.plausibility,
                                                                   title="POST VERIFICATION CHECKS")
        return VerificationModuleResults(plausibility=plaus_res, scanner=scanner_res, exploit=exploit_res,
                                         post_verification_plaus=post_verification_plaus)

    def __has_recently_been_verified(self, event_id, host, cves) -> bool:
        most_recent = self.db.get_most_recent_verification(host=host, cves=cves)
        if most_recent is not None:
            diff = TimeUtils.get_secs_between_timestamps(most_recent.timestamp, datetime.datetime.now())
            if diff <= self.verification_threshold:
                self.logger.warn(f"Cannot verify event, since host has been checked for this CVE {diff} secs ago.")
                return True
        self.logger.debug(
            f"Host has not been checked for this CVE within the last {self.verification_threshold} secs, proceed with verification...",
            1)
        self.db.add_vuln_verification(event_id, host, cves)
        return False

    def __exec_modules_of_class(self, arf_args: Namespace, event: SiemEvent, module_class: ModuleClass,
                                modules: [ModuleWithParamOverrides], title: str) -> VerificationModuleClassResult:
        self.logger.print_centered(title)
        module_results, successful_exec, erroneous_exec, details = [], [], [], []
        matching_modules = self.module_repo_cache.get_matching_exec_data(event_id=str(event.id),
                                                                         module_class=module_class,
                                                                         modules_with_override=modules)
        for module in matching_modules:
            if module:
                exec_result = self.module_executor.exec_and_evaluate(exec_data=module, event=event, arf_args=arf_args)
                details.append(exec_result)
                self.logger.debug(f"Module result: {exec_result}", 1)
                module_results.append((module.module_data.name, exec_result))
                if exec_result.module_exec_success:
                    successful_exec.append(module.module_data.name)
                else:
                    erroneous_exec.append(module.module_data.name)
        printable_results = [f"({name}, {details.__str__()})" for name, details in module_results]
        self.logger.debug(f"{module_class} modules execution results: {printable_results}.")
        if successful_exec:
            result = self.get_modules_mixed_results(details)
        else:
            result = None  # give no result if no module has been executed successfully
        return VerificationModuleClassResult(successful_modules=successful_exec, erroneous_modules=erroneous_exec,
                                             result=result, details=details)

    def get_modules_mixed_results(self, exec_details: list[ModuleExecDetails]) -> ModuleAggregatedSuccess:
        if all(exec_detail.module_success for exec_detail in exec_details):
            return ModuleAggregatedSuccess.ALL
        elif all(not exec_detail.module_success for exec_detail in exec_details):
            return ModuleAggregatedSuccess.NONE
        return ModuleAggregatedSuccess.MIXED

    def __filter_modules_for_vuln(self, vulns: list[ModulesForVuln], cves: list[str]) -> ModulesForVuln:
        modules = [v for v in vulns if any(c in v.cves for c in cves)]
        if len(modules) == 0:
            raise ModuleDefinitionError(f"No metadata file for modules for cves {cves} defined.")
        elif len(modules) == 1:
            return modules[0]
        raise ModuleDefinitionError(f"More than 1 metadata file for modules for cves {cves} defined.")

    def cleanup_on_exit(self) -> None:
        self.module_executor.cleanup_on_exit()
