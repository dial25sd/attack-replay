from typing import Any

from arf_io.interprocess import DockerHandler
from arf_io.ui import ArfLogger
from data_models.exec_data import ModuleExecDetails
from data_models.module_data import ModuleData


class ArfModuleAdapter:

    def __init__(self, docker_handler: DockerHandler):
        self.logger = ArfLogger.instance()
        self.docker_handler = docker_handler

    def exec_module(self, module_data: ModuleData, timeout: int, param_dict: dict[str, Any],
                    use_exit_code_for_success: bool) -> ModuleExecDetails:
        self.logger.info(f"Executing ARF Docker module '{module_data.name}' with a total timeout of {timeout} secs.")
        exit_code, output = self.docker_handler.run_and_delete(dockerfile_path=f"{module_data.path}",
                                                               container_name=module_data.name.lower(),
                                                               params=param_dict, timeout=timeout,
                                                               use_exit_code_for_success=use_exit_code_for_success)
        return ModuleExecDetails(output=output, exit_code=exit_code, params=param_dict)

    def cleanup_on_exit(self):
        self.docker_handler.remove_images()
