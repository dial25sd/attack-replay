import os
from typing import Any, Callable

from arf_io.exceptions import ExceptionHandler
from arf_io.files import YMLReader
from arf_io.ui import ArfLogger
from data_models.module_data import ModuleClass, ModuleData, ModulesForVuln
from utils import CVEUtils


class ModuleRepoParser:

    def __init__(self):
        self.logger = ArfLogger.instance()
        self.yml_parser = YMLReader()
        self.exception_handler = ExceptionHandler()

    def parse_modules(self, directory: str) -> tuple[list[ModuleData], list[ModulesForVuln]]:
        directory = directory if directory.endswith('/') else f"{directory}/"
        self.logger.info(f"Parsing module repo at: {directory}.")
        self.logger.info("Parsing ModulesForVuln...")
        vulns = self.search_directory(f"{directory}vulns", "vuln_", self.__parse_modules_for_vulns)
        self.logger.info("Parsing ModuleData...")
        modules = self.search_directory(f"{directory}modules", "module_", self.__parse_module_metadata)
        if len(modules) == 0:
            self.logger.warn("No modules found!")
        else:
            self.logger.success(
                f"Found & parsed {len(modules)} modules: {len([x for x in modules if x.module_class is ModuleClass.PLAUSIBILITY])} plausibility check(s), {len([x for x in modules if x.module_class is ModuleClass.SCANNER])} scanner(s) & {len([x for x in modules if x.module_class is ModuleClass.EXPLOIT])} exploit(s).")
            return modules, vulns

    def search_directory(self, directory: str, search_prefix: str, parse_fun: Callable) -> list[Any]:
        objects = []
        for item in os.scandir(directory):
            if item.is_file() and item.name.startswith(search_prefix) and item.name.endswith('.yml'):
                self.logger.debug(f"found yml file: {item.path}", 1)
                try:
                    yml = self.yml_parser.read_file(item.path)
                    objects.append(parse_fun(yml, directory))
                except Exception as e:
                    self.logger.warn(f"Unable to parse YML data for file '{item.name}': {e}.")
                    self.exception_handler.handle(e)
            elif not item.name.startswith('.') and item.is_dir():  # search recursively
                objects.extend(self.search_directory(item.path, search_prefix, parse_fun))
        return objects

    def __parse_module_metadata(self, yml: dict, yml_dir: str) -> ModuleData:
        module_data = ModuleData(**yml)
        if module_data.path is None:
            module_data.path = f"{yml_dir}/"
        module_data.validate()
        self.logger.debug(f"parsed module: {module_data}", 2)
        return module_data

    def __parse_modules_for_vulns(self, yml: dict, yml_dir: str) -> ModulesForVuln:
        modules_for_vuln = ModulesForVuln(**yml)
        modules_for_vuln.cves = [CVEUtils.sanitize_cve(CVEUtils.match_one_cve(cve)) for cve in modules_for_vuln.cves if
                                 CVEUtils.match_one_cve(cve) is not None]
        modules_for_vuln.validate()
        self.logger.debug(f"parsed modules for vulns: {modules_for_vuln}", 2)
        return modules_for_vuln
