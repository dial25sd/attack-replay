#!venv/bin/python

import atexit
import datetime
import os
import time
from argparse import Namespace
from typing import Optional

from arf_io.db import DbHandler, ReportGenerator
from arf_io.exceptions import ArfDbError, ExceptionHandler
from arf_io.interprocess import DockerHandler, MsfHandler, MsfRpcServerHandler
from arf_io.modules import ModuleRepoParser
from arf_io.ui import ArfArgParser, ArfLogger
from config import ArfConfig, MsfConfig
from data_models.report import ReportEntry
from data_models.shared import SiemEvent
from logic import EventDataHandler, EventProcessor, ModuleRepoCache, SuccessEvaluator
from utils import TimeUtils

logger = ArfLogger.instance()
exception_handler = ExceptionHandler()


def instant_exit(successful: bool = False):
    logger.info("Stopping and cleaning up...")
    try:
        event_processor.cleanup_on_exit()
        db.on_end() if db else None
        msf_handler.terminate() if msf_handler else None
        msf_rpc_handler.terminate() if msf_rpc_handler else None
    except:
        pass
    if logger is not None:
        logger.success("Execution finished successfully.") if successful else logger.error("Abort.")
    if not successful:
        os._exit(1)
    os._exit(0)


def greet_and_get_args() -> Namespace:
    logger.print_greeting()
    arf_param_handler = ArfArgParser()
    try:
        logger.print_centered_hollow(f"STARTING UP")
        args = arf_param_handler.parse_args()
        logger.set_verbosity(args.verbose)
        return args
    except Exception as e:
        logger.debug(f"Error parsing args: {e}")
        instant_exit()


def init_db(threshold: int) -> DbHandler:
    try:
        return DbHandler(db_host=args.db_host, db_port=args.db_port, db_name=args.db_name, arf_args=args, verification_threshold=threshold)
    except ArfDbError as e:
        logger.error(f"Unable to connect to ARF DB: {e}")
        instant_exit()


def connect_to_msf() -> (MsfHandler, MsfRpcServerHandler):
    try:
        msf_rpc_handler = MsfRpcServerHandler(MsfConfig.HOST, MsfConfig.PORT, MsfConfig.USER, MsfConfig.PWD)
        msf_handler = MsfHandler(MsfConfig.HOST, MsfConfig.PORT, MsfConfig.USER, MsfConfig.PWD)
        return msf_handler, msf_rpc_handler
    except Exception as e:
        logger.error(str(e))
        instant_exit()


def connect_to_docker():
    try:
        return DockerHandler()
    except Exception as e:
        logger.error(str(e))
        instant_exit()


def read_and_cache_module_repo(db: DbHandler) -> ModuleRepoCache:
    try:
        module_repo_cache = ModuleRepoCache(db_handler=db)
        modules, vulns = ModuleRepoParser().parse_modules(directory=args.module_repo)
        module_repo_cache.write_modules_for_vulns_to_cache(vulns)
        module_repo_cache.write_modules_to_cache(modules)
        return module_repo_cache
    except FileNotFoundError as e:
        exception_handler.handle(e, msg=f"Unable to load module repo: {e}")
        instant_exit()


def verify_events(events: list[SiemEvent]) -> None:
    logger.increment_event_count(len(events))
    try:
        event_processor.process_all_events(events, args)
    except Exception as e:
        exception_handler.handle(e)
        instant_exit()


def verify_events_continuously() -> None:
    while True:
        start = datetime.datetime.now()
        events = db.get_unprocessed_siem_events()
        if events:
            verify_events(events=events)
        time_diff = TimeUtils.get_secs_between_timestamps(start, datetime.datetime.now())
        if time_diff <= ArfConfig.POLL_INTERVAL_CONTINUOUS_MODE:
            sleep_time = ArfConfig.POLL_INTERVAL_CONTINUOUS_MODE - time_diff
            logger.debug(f"Now sleeping for {sleep_time} seconds...", 1)
            time.sleep(sleep_time)


def conclude_exec(db: Optional[DbHandler]) -> None:
    logger.print_centered_hollow(f"FINISHING EXECUTION")
    if db is not None:
        data = db.get_verification_data()
        if logger is not None:
            exploitable = SuccessEvaluator.get_exploitable_count(data)
            vulnerable = SuccessEvaluator.get_vulnerable_count(data)
            logger.warn(f"Total exec result: {exploitable} EXPLOITABLE, {vulnerable} VULNERABLE of {len(data)} events.")
        report_data = [ReportEntry.incorporate_cached_data(cached) for cached in data]
        try:
            db.conclude_exec_stats(report_data)
        except:
            logger.warn("Unable to write concluding exec data to DB!")
        try:
            ReportGenerator(args.report_dir).write_report(report_data)
        except Exception as e:
            logger.error(f"Unable to write report: {e}")
    instant_exit(successful=True)


if __name__ == '__main__':
    db: Optional[DbHandler] = None
    docker_handler: Optional[DockerHandler] = None
    msf_handler: Optional[MsfHandler] = None
    msf_rpc_handler: Optional[MsfRpcServerHandler] = None

    try:
        args = greet_and_get_args()
        # start + connect to dependencies
        db = init_db(args.threshold)
        msf_handler, msf_rpc_handler = connect_to_msf()
        docker_handler = connect_to_docker()
        atexit.register(msf_rpc_handler.terminate)

        module_repo_cache = read_and_cache_module_repo(db=db)
        event_processor = EventProcessor(module_repo_cache=module_repo_cache, internal_subnets=args.subnets,
                                         msf_handler=msf_handler, docker_handler=docker_handler,
                                         timeout=args.module_timeout, db=db, verification_threshold=args.threshold)

        if args.continuous_mode is False:
            EventDataHandler(db=db).read_and_cache_events(file_path=args.event_file)
            events = db.get_cached_siem_events()
            verify_events(events)
        else:
            verify_events_continuously()
    except:
        pass
    finally:
        conclude_exec(db=db)
