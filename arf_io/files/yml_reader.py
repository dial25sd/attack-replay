from typing import Any

import yaml

from arf_io.ui.arf_logger import ArfLogger


class YMLReader:
    def __init__(self):
        self.logger = ArfLogger.instance()

    def read_file(self, path: str) -> dict[str, Any]:
        with open(path, "r") as file_stream:
            try:
                return yaml.safe_load(file_stream)
            except yaml.YAMLError as e:
                self.logger.error(f"Error reading YAML file: {e}")
