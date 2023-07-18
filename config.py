from arf_io.exceptions import ModuleTimeoutError, VerificationPermissionError
from utils import RandomUtils


class ArfConfig:
    DEBUG = False
    RAISE_ALL_ERRORS = False
    UNCRITICAL_EXCEPTIONS = [ModuleTimeoutError, VerificationPermissionError]  # only relevant for DEBUG
    MAX_SESSION_TIMEOUT_SECS = 30  # for MSF modules
    POLL_INTERVAL_CONTINUOUS_MODE = 10  # waiting time for next poll in continuous mode
    SIEM_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%f%z'


class ArfLogConfig:
    LOGGER_NAME = "arf"
    FILE = "attack-replay.log"
    DEBUG = ArfConfig.DEBUG
    LINE_LENGTH = 95


class ArfLogColors:
    warn = "\033[1m\033[33m"
    error = "\033[1m\033[91m"
    prompt = "\033[1m\033[36m"
    success = "\033[1m\033[32m"
    info = "\033[97m"
    background = "\033[36m"
    end = "\033[0m"


class MsfConfig:
    HOST = "127.0.0.1"
    PORT = str(RandomUtils.get_random_port())
    PWD = RandomUtils.get_random_password()
    USER = "arf"
    CONN_MAX_TRIES = 10
    CONN_TIME_SLEEP = 4
    SESS_TIME_SLEEP = 3


class ArfDbTables:
    CACHED_EVENTS = "cached_events"  # for cached events read from file
    EVENTS = "events"  # for event sync in continuous mode
    ARF_EXEC_STATS = "arf_exec_stats"
    VULN_METADATA = "cached_vulns"
    MODULES = "cached_modules"
    VULN_VERIFICATION = "vuln_verification"
    REPORT_DATA = "cached_report_data"
    CVSS = "cached_cvss_scores"


class ApiConfig:
    CVSS_API_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/CVE-{ID}"
