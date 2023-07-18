import time

import math

from config import ArfConfig, ArfLogColors as Colors, ArfLogConfig
from .file_logger import FileLogger


class ArfLogger:
    _instance = None
    _file_logger: FileLogger = None
    _debug: bool = False

    _event_count = 0
    _current_event_no = 0

    def __init__(self):
        raise RuntimeError('ArfLogger is a singleton, please call instance() instead')

    @classmethod
    def instance(cls):
        if not cls._instance:
            cls._instance = cls.__new__(cls)
            cls._file_logger = FileLogger.instance(logger_name=ArfLogConfig.LOGGER_NAME, file_name=ArfLogConfig.FILE,
                                                   debug=ArfLogConfig.DEBUG)
            cls._debug = ArfLogConfig.DEBUG
        return cls._instance

    @classmethod
    def set_verbosity(cls, verbose: bool):
        if verbose:  # ignore flag if not set
            cls._debug = verbose
            cls._file_logger.set_verbosity(verbose=verbose)

    @classmethod
    def increment_event_no(cls) -> None:
        cls._current_event_no += 1

    @classmethod
    def increment_event_count(cls, count: int) -> None:
        cls._event_count += count

    def info(self, text: str) -> None:
        complete_text = f"{Colors.info}[i]  {text}"
        self._file_logger.info(self.__get_log_str_file(complete_text))
        print(self.__get_log_str_stdout(complete_text))

    def success(self, text: str) -> None:
        complete_text = f"{Colors.success}[+]  {text}"
        self._file_logger.info(self.__get_log_str_file(complete_text))
        print(self.__get_log_str_stdout(complete_text))

    def prompt(self, text: str) -> str:
        complete_text = f"{Colors.prompt}[?]  {text}{Colors.end}: "
        answer = input(self.__get_log_str_stdout(complete_text))
        self._file_logger.info(self.__get_log_str_file(complete_text))
        msg = f"Prompted, received input: '{answer}'"
        self.debug(msg, 1)
        return answer

    def error(self, text: str) -> None:
        complete_text = f"{Colors.error}[X]  {text}"
        self._file_logger.error(self.__get_log_str_file(complete_text))
        print(self.__get_log_str_stdout(complete_text))

    def warn(self, text: str) -> None:
        complete_text = f"{Colors.warn}[!]  {text}"
        self._file_logger.warn(self.__get_log_str_file(complete_text))
        print(self.__get_log_str_stdout(complete_text))

    def debug(self, text: str, depth: int = 0) -> None:
        indent = f"   └── " if depth > 0 else ""
        for i in range(depth - 1):
            indent = f"     {indent}"
        complete_text = f"{Colors.background}[d]  {indent}{text}"
        self._file_logger.debug(self.__get_log_str_file(complete_text))
        if self._debug:
            print(self.__get_log_str_stdout(complete_text))

    def print_greeting(self) -> None:
        print(f"\n \
                                                       M U N I C H                                                \n \
        ")
        if not ArfConfig.DEBUG: time.sleep(0.7)
        print(f"\
                                                     ARE YOU READY FOR                                                \n \
        ")
        if not ArfConfig.DEBUG: time.sleep(0.7)
        print('\n \
                 888    888                      888                                    888                   \n \
                 888    888                      888                                    888                   \n \
                 888    888                      888                                    888                   \n \
         8888b.  888888 888888  8888b.   .d8888b 888  888      888d888 .d88b.  88888b.  888  8888b.  888  888 \n \
            "88b 888    888        "88b d88P"    888 .88P      888P"  d8P  Y8b 888 "88b 888     "88b 888  888 \n \
        .d888888 888    888    .d888888 888      888888K       888    88888888 888  888 888 .d888888 888  888 \n \
        888  888 Y88b.  Y88b.  888  888 Y88b.    888 "88b      888    Y8b.     888 d88P 888 888  888 Y88b 888 \n \
        "Y888888  "Y888  "Y888 "Y888888  "Y8888P 888  888      888     "Y8888  88888P"  888 "Y888888  "Y88888 \n \
                                                                               888                        888 \n \
                                                                               888                   Y8b d88P \n \
                                                                               888                    "Y88P"  \n')
        if not ArfConfig.DEBUG: time.sleep(0.7)
        print(f"{Colors.info}> Use --help for an overview of options.{Colors.end}")
        print(f"{Colors.info}> Gracefully stop the application at any time using CTRL+C.")
        print(
            f"{Colors.info}> Unauthorized use of this application might be illegal. Consider reading the docs before execution.{Colors.end} \n")

        self._file_logger.info("ATTACK REPLAY STARTING UP")

    def print_centered(self, text: str) -> None:
        length = (ArfLogConfig.LINE_LENGTH - len(text) - 2) / 2
        dashes_left = math.floor(length)
        dashes_right = math.ceil(length)
        self.info(f"{'-' * dashes_left} {text} {'-' * dashes_right}")

    def print_centered_hollow(self, text: str) -> None:
        self.info(f"{ArfLogConfig.LINE_LENGTH * '-'}")
        length = (ArfLogConfig.LINE_LENGTH - len(text) - 4) / 2
        spaces_left = math.floor(length)
        spaces_right = math.ceil(length)
        self.info(f"|{' ' * spaces_left} {text} {' ' * spaces_right}|")
        self.info(f"{ArfLogConfig.LINE_LENGTH * '-'}")

    def __get_log_str_stdout(self, text) -> str:
        current = self.print_fixed_digits(self._current_event_no, 2)
        total = self.print_fixed_digits(self._event_count, 2)
        return f"{Colors.background}ARF @ {time.strftime('%X'):9} [{current}/{total}]{Colors.end}  {text}{Colors.end}"

    def __get_log_str_file(self, text) -> str:
        current = self.print_fixed_digits(self._current_event_no, 2)
        total = self.print_fixed_digits(self._event_count, 2)
        return f"{Colors.background}[{current}/{total}]{Colors.end}  {text}{Colors.end}"

    def print_fixed_digits(self, n, digits) -> str:
        return "{: >{}}".format(n, digits)
