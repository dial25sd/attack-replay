from typing import Union

from arf_io.exceptions import ModuleLoadError
from arf_io.ui import ArfLogger
from arf_io.interprocess import MsfHandler
from data_models.exec_data import ModuleExecDetails
from data_models.module_data import ModuleClass, ModuleData
from pymetasploit3.msfrpc import MsfModule
from utils import MsfUtils


class MsfModuleAdapter:

    def __init__(self, msf_handler: MsfHandler):
        self.logger = ArfLogger.instance()
        self.msf_handler = msf_handler

    def exec_module(self, module_data: ModuleData, timeout_secs: int, param_dict: dict,
                    payload_param_dict: dict) -> ModuleExecDetails:
        module = self.msf_handler.get_module_by_path(complete_module_path=module_data.path)
        if module is not None:
            self.logger.debug(f"Got MSF module: {module.modulename}")
            for name, value in param_dict.items():
                self.msf_handler.set_msf_module_param(module, name, value)
            payload = self.__configure_msf_module_payload(module, module_data, param_dict=payload_param_dict,
                                                          specified_payload_name=param_dict.get('PAYLOAD'))
            self.msf_handler.check_for_missing_param_values(module_data.path, module)
            self.logger.info(f"Executing MSF module {module.modulename} with a total timeout of {timeout_secs} secs.")
            exec_data = self.msf_handler.exec_module(module, module_class=module_data.module_class, payload=payload,
                                                     exec_mode=module_data.exec_mode, timeout_secs=timeout_secs)
            exec_data.params = param_dict
            return exec_data
        raise ModuleLoadError(f"Cannot load MSF module {module_data.name}.")

    def __configure_msf_module_payload(self, exploit_module: MsfModule, module_data: ModuleData, param_dict: dict,
                                       specified_payload_name=None) -> Union[MsfModule, None]:
        if module_data.module_class is not ModuleClass.EXPLOIT:
            return None
        if specified_payload_name:
            payload_path = specified_payload_name
            self.logger.debug(f"Payload has been specified explicitly: {payload_path}")
        else:
            payload_path = MsfUtils.get_default_payload(exploit_module.payloads)
            self.logger.debug(f"Payload has been selected according to priority list: {payload_path}")
        payload_path_internal = f"payload/{payload_path}"
        self.logger.debug(f"Selected payload {payload_path}")
        payload = self.msf_handler.get_module_by_path(complete_module_path=payload_path_internal)
        if payload is None:
            raise ModuleLoadError(f"Cannot load MSF Payload for module {module_data.path}")
        for name, value in param_dict.items():
            self.msf_handler.set_msf_module_param(payload, name, value)
        self.msf_handler.check_for_missing_param_values(payload_path, payload)
        return payload
