import os
from typing import Any

from arf_io.exceptions import ArfArgumentValidationError


class ValidatorUtils:

    @staticmethod
    def validate_timespan(value: Any) -> int:
        try:
            if int(value) <= 0:
                raise ArfArgumentValidationError("")
            return int(value)
        except Exception as e:
            raise ArfArgumentValidationError("Timespan must be a positive non-zero integer.") from e

    @staticmethod
    def validate_port(value: Any) -> int:
        try:
            value_int = int(value)
        except Exception as e:
            raise ArfArgumentValidationError("Timespan must be a positive non-zero integer.") from e
        if 0 < value_int < 65536:
            return value_int
        raise ArfArgumentValidationError("Port number must be between 1 and 65535.")

    @staticmethod
    def validate_readable_filepath(file_path: str) -> str:
        if ValidatorUtils.__is_file(file_path) and ValidatorUtils.__is_readable(file_path=file_path):
            return file_path
        raise ArfArgumentValidationError("Path is not a valid and readable filepath")

    @staticmethod
    def validate_writable_filepath(file_path: str):
        if ValidatorUtils.__is_file(file_path) and ValidatorUtils.__is_writable(path=file_path):
            return file_path
        raise ArfArgumentValidationError("Path is not a valid and writable filepath")

    @staticmethod
    def validate_writable_dir(dir: str) -> str:
        if ValidatorUtils.__is_a_dir(dir) and ValidatorUtils.__is_writable(path=dir):
            return dir
        raise ArfArgumentValidationError("Path is not a valid and writeable directory")

    @staticmethod
    def __is_file(file_path: str) -> bool:
        _, file_extension = os.path.splitext(file_path)
        return bool(file_extension)

    @staticmethod
    def __is_a_dir(file_path: str) -> bool:
        return file_path.endswith('/')

    @staticmethod
    def __is_writable(path: str) -> bool:
        dir_path = os.path.dirname(path)
        if dir_path and not os.path.exists(dir_path):
            return False
        if os.path.isdir(dir_path) and os.access(dir_path, os.W_OK):
            return True
        if not dir_path:  # means we're in the current workdir
            return True
        return False

    @staticmethod
    def __is_readable(file_path: str) -> bool:
        if not os.path.exists(file_path):
            return False
        try:
            with open(file_path, "r"):
                pass
        except Exception as e:
            return False
        return True
