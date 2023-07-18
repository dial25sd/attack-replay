from argparse import Namespace
from datetime import datetime, timedelta
from typing import Optional

from bson.objectid import ObjectId

from arf_io.exceptions import ArfDbError
from arf_io.ui import ArfLogger
from config import ArfConfig, ArfDbTables
from data_models.exec_data import ArfExecStats, VerificationModuleResults, VerificationOverallResult, VulnVerification, \
    VulnerabilityState
from data_models.module_data import ModuleData, ModulesForVuln
from data_models.report import CachedVerificationData, ReportEntry
from data_models.shared import CvssForVuln, Host, SiemEvent
from utils import IPAddress, Serializer
from .db_adapter import DbAdapter


class DbHandler:
    current_arf_exec_id: Optional[ObjectId] = None

    def __init__(self, db_host: IPAddress, db_port: int, db_name: str, arf_args: Namespace, verification_threshold: int):
        self.debug = ArfConfig.DEBUG
        self.logger = ArfLogger.instance()
        self.logger.info(f"Trying to connect to MongoDB at {db_host}:{db_port}.")
        self.db = DbAdapter(db_host=db_host, db_port=db_port, db_name=db_name)
        self.log_arf_start(arf_args=arf_args)
        self.on_start(verification_threshold)

    def __clear_caches(self) -> None:
        self.logger.debug("Clearing caches...", 1)
        self.db.drop_collection(ArfDbTables.CACHED_EVENTS)
        self.db.drop_collection(ArfDbTables.VULN_METADATA)
        self.db.drop_collection(ArfDbTables.MODULES)
        self.db.drop_collection(ArfDbTables.REPORT_DATA)
        self.db.drop_collection(ArfDbTables.CVSS)

    def on_start(self, vuln_verification_threshold_secs: int) -> None:
        self.__clear_caches()
        self.remove_old_vuln_verifications(vuln_verification_threshold_secs)

    def on_end(self) -> None:
        if not self.debug:
            self.__clear_caches()
        self.log_arf_end()

    def log_arf_start(self, arf_args: Namespace) -> None:
        arf_exec = ArfExecStats(datetime.now(), vars(arf_args))
        self.current_arf_exec_id = self.db.create_one(ArfDbTables.ARF_EXEC_STATS, arf_exec)
        if not self.current_arf_exec_id:
            raise ArfDbError("Fatal: Cannot write ARF Exec data to DB.")

    def log_arf_end(self) -> None:
        self.logger.info("Writing exec data to DB...")
        self.db.update(ArfDbTables.ARF_EXEC_STATS, {"_id": self.current_arf_exec_id}, {"$set": {"end": datetime.now()}})

    def write_siem_events(self, events: list[SiemEvent]) -> None:
        created = self.db.create_many(ArfDbTables.CACHED_EVENTS, events)
        self.logger.info(f"Cached {len(created)} SIEM event(s).")

    def write_module_metadata(self, modules: list[ModuleData]) -> None:
        created = self.db.create_many(ArfDbTables.MODULES, modules)
        self.logger.info(f"Cached metadata for {len(created)} module(s).")

    def write_vuln_to_modules(self, modules: list[ModulesForVuln]) -> None:
        created = self.db.create_many(ArfDbTables.VULN_METADATA, modules)
        self.logger.info(f"Cached metadata for {len(created)} vuln(s).")

    def get_cached_siem_events(self) -> list[SiemEvent]:
        self.logger.debug("Getting cached SIEM events from DB")
        events = self.db.read_many(ArfDbTables.CACHED_EVENTS, SiemEvent)
        if events:
            self.logger.debug(f"Read {len(events)} SIEM event(s) from cache.", 1)
        else:
            self.logger.warn(f"No SIEM events found in cache!")
        return events

    def get_unprocessed_siem_events(self) -> list[SiemEvent]:
        self.logger.info("Getting synced SIEM event from queue...")
        events_dict = self.db.read_and_delete_all(ArfDbTables.EVENTS)
        if events_dict:
            events = [SiemEvent.from_json(event) for event in events_dict]
            self.logger.debug(f"Read {len(events)} SIEM event(s) from queue.", 1)
            return events
        self.logger.warn(f"No unprocessed SIEM event found in queue!")
        return []

    def search_module(self, query: dict) -> ModuleData:
        self.logger.debug(f"Searching for modules in DB using query {query}.", 1)
        result = self.db.read_one(ArfDbTables.MODULES, ModuleData, query)
        self.logger.debug(f"Got result: {result}.", 2)
        return result

    def search_modules_for_vuln(self, query: dict) -> list[ModulesForVuln]:
        self.logger.debug(f"Searching for modules for vuln in DB using query {query}.", 1)
        results = self.db.read_many(ArfDbTables.VULN_METADATA, ModulesForVuln, query)
        self.logger.debug(f"Got {len(results)} results: {[str(x) for x in results]}.", 2)
        return results

    def add_vuln_verification(self, event_id: str, host: Host, cves: list[str]) -> Optional[ObjectId]:
        self.logger.debug(f"Add VulnVerification entry for event {event_id} to DB.")
        verification_obj = VulnVerification(host, datetime.now(), cves=cves)
        return self.db.create_one(ArfDbTables.VULN_VERIFICATION, verification_obj)

    def get_most_recent_verification(self, host: Host, cves: list[str]) -> Optional[VulnVerification]:
        pipeline = [{"$match": {"host.ip": str(host.ip), "host.port": host.port, "cves": {"$in": cves}}},
                    {"$sort": {"timestamp": -1}}, {"$limit": 1}]
        return self.db.read_one(ArfDbTables.VULN_VERIFICATION, VulnVerification, pipeline=pipeline)

    def remove_old_vuln_verifications(self, vuln_verification_threshold_secs: int) -> int:
        current_time = datetime.now()
        threshold_time = current_time - timedelta(seconds=vuln_verification_threshold_secs)
        query = {"timestamp": {"$lt": threshold_time}}
        self.logger.debug("Clearing outdated verification entries...", 1)
        return self.db.delete(ArfDbTables.VULN_VERIFICATION, query, multi=True)

    def write_verification_data(self, data: CachedVerificationData) -> Optional[ObjectId]:
        self.logger.debug("Adding cached verification data to DB.")
        return self.db.create_one(ArfDbTables.REPORT_DATA, data)

    def conclude_verification_data(self, event_id: ObjectId, module_res: Optional[VerificationModuleResults],
                                   overall_res: Optional[VerificationOverallResult], verification_details: str) -> None:
        self.logger.debug(f"Completing cached verification data for event {event_id} with results: {overall_res}.")
        verification_success = overall_res is not None and overall_res.vuln_state is not VulnerabilityState.UNKNOWN
        self.db.update(ArfDbTables.REPORT_DATA, {"event._id": event_id}, {
            "$set": {"end": datetime.now(), "overall_result": Serializer.serialize_dataclass(overall_res),
                     "plaus_result": Serializer.serialize_dataclass(
                         module_res.plausibility) if module_res is not None else None,
                     "scanner_result": Serializer.serialize_dataclass(
                         module_res.scanner) if module_res is not None else None,
                     "exploit_result": Serializer.serialize_dataclass(
                         module_res.exploit) if module_res is not None else None,
                     "verification_success": verification_success, "verification_details": verification_details}})
        successful_plaus_count = len(module_res.plausibility.successful_modules) if module_res else 0
        successful_scanner_count = len(module_res.scanner.successful_modules) if module_res else 0
        successful_exploit_count = len(module_res.exploit.successful_modules) if module_res else 0
        total_successful_count = successful_plaus_count + successful_scanner_count + successful_exploit_count
        self.db.update(ArfDbTables.ARF_EXEC_STATS, {"_id": self.current_arf_exec_id}, {"$set": {"end": datetime.now()},
                                                                                       "$inc": {
                                                                                           "total_successful_module_count": total_successful_count,
                                                                                           "total_successful_exploit_count": successful_exploit_count,
                                                                                           "total_successful_scanner_count": successful_scanner_count,
                                                                                           "total_successful_plaus_count": successful_plaus_count}})
        if verification_success:
            self.db.update(ArfDbTables.ARF_EXEC_STATS, {"_id": self.current_arf_exec_id},
                           {"$inc": {"successfully_verified_events": 1}})

    def conclude_exec_stats(self, report_entries: list[ReportEntry]):
        self.db.update(ArfDbTables.ARF_EXEC_STATS, {"_id": self.current_arf_exec_id},
                       {"$set": {"verification_data": Serializer.serialize_dataclass_list(report_entries)}})

    def get_verification_data(self) -> list[CachedVerificationData]:
        self.logger.debug("Query DB for report data")
        return self.db.read_many(ArfDbTables.REPORT_DATA, CachedVerificationData)

    def get_cvss_score(self, cve_id: str) -> Optional[CvssForVuln]:
        self.logger.debug(f"Query DB for CVSS score for CVE ID {cve_id}", 1)
        cvss = self.db.read_one(ArfDbTables.CVSS, CvssForVuln, query={"cve": cve_id})
        if cvss is None:
            self.logger.debug("No cached CVSS score found", 2)
        return cvss

    def write_cvss_score(self, cvss: CvssForVuln) -> Optional[ObjectId]:
        return self.db.create_one(ArfDbTables.CVSS, cvss)
