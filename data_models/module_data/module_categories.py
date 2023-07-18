from utils import ArfEnum


class ModuleClass(ArfEnum):
    SCANNER = "scanner"
    EXPLOIT = "exploit"
    PLAUSIBILITY = "plausibility"
    PARAM_SCANNER = "param_scanner"


class ModuleType(ArfEnum):
    MSF = "msf"
    STANDALONE = "standalone"
