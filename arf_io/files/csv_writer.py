import csv
from typing import Union

from arf_io.exceptions import ArfReportError
from arf_io.ui.arf_logger import ArfLogger
from utils import ValidatorUtils


class CsvWriter:

    def __init__(self, file_path: str):
        self.logger = ArfLogger.instance()
        self.file_path = self.__get_valid_csv_path(file_path)

    def __get_valid_csv_path(self, file_path: str) -> str:
        try:
            ValidatorUtils.validate_writable_filepath(file_path)
            return file_path
        except Exception as e:
            self.logger.error(f"Path '{file_path}' is either not a file or not writeable: {e}")
            raise ArfReportError("Invalid path: cannot create a report file in the given directory") from e

    def create_file_with_field_names(self, field_names: list[str]) -> None:
        self.logger.debug("Creating CSV file and writing field names")
        with open(self.file_path, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(field_names)

    def write_many(self, entries: list[list[Union[str, int, float]]]) -> None:
        self.logger.debug("Writing entries to CSV file")
        with open(self.file_path, 'a', newline='') as csvfile:
            csv_writer = csv.writer(csvfile, escapechar='\\')
            csv_writer.writerows(entries)
