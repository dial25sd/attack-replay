from arf_io.db import DbHandler
from arf_io.ui import ArfLogger
from data_models.exec_data import ModuleExecData
from data_models.module_data import ModuleClass, ModuleData, ModuleWithParamOverrides, ModulesForVuln


class ModuleRepoCache:

    def __init__(self, db_handler: DbHandler):
        self.logger = ArfLogger.instance()
        self.db = db_handler

    def write_modules_to_cache(self, modules: [ModuleData]) -> None:
        self.db.write_module_metadata(modules)

    def get_module_by_name(self, name: str, module_class: ModuleClass) -> ModuleData:
        query = {"module_class": str(module_class).lower(), "name": name}
        return self.db.search_module(query)

    def write_modules_for_vulns_to_cache(self, modules_for_vulns: [ModulesForVuln]):
        self.db.write_vuln_to_modules(modules_for_vulns)

    def get_modules_for_vuln(self, cves) -> [ModulesForVuln]:
        self.logger.info(f"Searching for module names by cve '{','.join(cves)}'")
        query = {"cves": {"$in": cves}}
        return self.db.search_modules_for_vuln(query)

    def get_matching_exec_data(self, module_class: ModuleClass, modules_with_override: [ModuleWithParamOverrides],
                               event_id: str) -> [ModuleExecData]:
        self.logger.info(
            f"Searching for modules of class '{module_class}': {len(modules_with_override)} specified in ModulesForVuln.")
        matching_modules = [module for m in modules_with_override if
                            (module := self.get_module_by_name(name=m.name, module_class=module_class)) is not None]
        module_exec_data = []
        if matching_modules:
            for mod in modules_with_override:
                bare_mod = next((module for module in matching_modules if module.name == mod.name), None)
                if bare_mod:
                    mod = ModuleExecData(bare_mod, mod.parameters, mod.payload_parameters, mod.success, mod.result)
                    module_exec_data.append(mod)
                else:
                    self.logger.warn(f"No matching bare module data found for '{mod.name}'.")
        if module_class is ModuleClass.PARAM_SCANNER:
            self.logger.success(f"Found {len(module_exec_data)} matching '{module_class}' module(s).")
        else:
            self.logger.success(
                f"Found {len(module_exec_data)} matching '{module_class}' module(s) for event {event_id}.")
        return module_exec_data
