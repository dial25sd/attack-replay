import logging


class FileLogger:
    _instance = None
    _logger: logging.Logger
    _handler: logging.Handler

    def __init__(self):
        raise RuntimeError('FileLogger is a singleton, please call instance() instead')

    @classmethod
    def instance(cls, logger_name: str, file_name: str, debug: bool):
        if not cls._instance:
            cls._instance = cls.__new__(cls)
            cls._logger = logging.getLogger(logger_name)
            formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            cls._handler = logging.FileHandler(file_name, mode='w')
            cls._handler.setFormatter(formatter)
            level = logging.DEBUG if debug else logging.INFO
            cls._logger.setLevel(level)
            cls._logger.addHandler(cls._handler)
        return cls._instance

    @classmethod
    def set_verbosity(cls, verbose: bool):
        cls._logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    def info(self, text: str) -> None:
        self._logger.info(text)

    def warn(self, text: str) -> None:
        self._logger.warning(text)

    def error(self, text: str) -> None:
        self._logger.error(text)

    def debug(self, text: str) -> None:
        self._logger.debug(text)
