from dataclasses import asdict, fields
from datetime import datetime

from arf_io.files import CsvWriter
from arf_io.ui import ArfLogger
from data_models.report import ReportEntry


class ReportGenerator:

    def __init__(self, report_dir: str):
        self.logger = ArfLogger.instance()
        if not report_dir.endswith('/'):
            report_dir = f"{report_dir}/"
        self.report_path = f"{report_dir}arf-report_{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"

    def write_report(self, report_entries: list[ReportEntry]) -> None:
        if len(report_entries) > 0:
            writer = CsvWriter(self.report_path)
            self.logger.info(f"Writing ARF report to file...")
            column_names = self.get_column_names(report_entries[0])
            writer.create_file_with_field_names(column_names)
            report_data = self.convert_report_entries(report_entries)
            writer.write_many(report_data)
            self.logger.success(f"Wrote report with {len(report_entries)} line(s) to '{self.report_path}'.")
        else:
            self.logger.warn(f"No report data to write!")

    def get_column_names(self, report_entry: ReportEntry) -> list[str]:
        field_names = [field.name for field in fields(report_entry)]
        return field_names

    def convert_report_entries(self, entries: list[ReportEntry]) -> list[list]:
        lines_values = []
        for obj in entries:
            obj_dict = asdict(obj)
            line_values = list(obj_dict.values())
            lines_values.append(line_values)
        return lines_values
