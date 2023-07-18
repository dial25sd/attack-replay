import traceback

from arf_io.ui import ArfLogger
from config import ArfConfig


class ExceptionHandler:

    def __init__(self):
        self.logger = ArfLogger.instance()

    def handle(self, e: Exception, msg: str = "", reraise: bool = False, reraise_critical: bool = False) -> None:
        msg = msg if msg else str(e)
        self.logger.error(msg)
        if not any(isinstance(e, u) for u in ArfConfig.UNCRITICAL_EXCEPTIONS):
            self.logger.debug(traceback.format_exc())
        if reraise:
            raise
        if ArfConfig.RAISE_ALL_ERRORS and not any(isinstance(e, u) for u in ArfConfig.UNCRITICAL_EXCEPTIONS):
            raise
        if reraise_critical and ArfConfig.DEBUG and not any(isinstance(e, u) for u in ArfConfig.UNCRITICAL_EXCEPTIONS):
            raise
