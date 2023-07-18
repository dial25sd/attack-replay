from dataclasses import dataclass

from arf_io.exceptions import ModuleDefinitionError
from data_models.module_data import ModuleWithParamOverrides


@dataclass
class ModulesForVuln:
    cves: list[str]
    plausibility: list['ModuleWithParamOverrides']
    scanners: list['ModuleWithParamOverrides']
    exploits: list['ModuleWithParamOverrides']

    def __post_init__(self):
        self.plausibility = [ModuleWithParamOverrides(**p) for p in self.plausibility] if self.plausibility else []
        self.scanners = [ModuleWithParamOverrides(**s) for s in self.scanners] if self.scanners else []
        self.exploits = [ModuleWithParamOverrides(**e) for e in self.exploits] if self.exploits else []

    def __str__(self) -> str:
        return f"ModulesForVuln(cves: {self.cves}, plausibility: #{len(self.plausibility)}, scanners: #{len(self.scanners)}, exploits: #{len(self.exploits)})"

    def validate(self) -> None:
        if not self.cves:
            raise ModuleDefinitionError(f"ModulesForVuln must have CVEs defined.")
        if not self.scanners and not self.exploits:
            raise ModuleDefinitionError(f"No scanner or exploit modules for vuln {self.cves} found.")
