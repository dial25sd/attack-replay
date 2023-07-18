from argparse import Namespace
from typing import Any, Optional, Tuple

from arf_io.exceptions import ExceptionHandler, ParamEvalError
from arf_io.ui import ArfLogger
from data_models.module_data import EvaluatedParam, ModuleParam
from data_models.shared import SiemEvent
from .param_evaluator import ParamEvaluator


class ParamHandler:

    def __init__(self, module_executor: 'ModuleExecutor'):
        self.logger = ArfLogger.instance()
        self.evaluator = ParamEvaluator(module_executor=module_executor)
        self.exception_handler = ExceptionHandler()

    def get_all_param_values(self, arf_args: Namespace, event: SiemEvent, params: list[ModuleParam],
                             overridden: list[ModuleParam]) -> dict:
        overridden = overridden or []
        params = params or []
        param_dict = {}
        param_names = [param.name for param in params]
        overridden_names = [param.name for param in overridden]
        all_names = list(set(param_names + overridden_names))
        for param_name in all_names:
            val = None
            param = next((x for x in params if x.name == param_name), None)
            overridden_param = next((x for x in overridden if x.name == param_name), None)
            used_param = param
            try:
                automatic_val, used_param = self.__get_original_or_override_val(param, overridden_param, arf_args,
                                                                                event)
                val = self.__prompt_manual_value(arf_args, automatic_val, used_param, val) or automatic_val
            except ParamEvalError:
                if used_param.configurable and arf_args.manual_mode:
                    val = self.__prompt_manual_value_on_err(used_param, val)
                else:
                    raise
                if not val:
                    raise
            param_dict.update({param_name: val})
        return param_dict

    def __get_original_or_override_val(self, param: ModuleParam, overridden: ModuleParam, arf_args: Namespace,
                                       event: SiemEvent) -> Tuple[Optional[EvaluatedParam], Optional[ModuleParam]]:
        if not overridden:
            return self.__get_param_val(param, event, arf_args), param
        if not param or param.name == overridden.name:
            return self.__get_param_val(overridden, event, arf_args), overridden
        return None, None

    def __get_param_val(self, param: ModuleParam, event: SiemEvent, arf_args: Namespace) -> EvaluatedParam:
        value = None
        use_default = False
        if param.value is None:
            use_default = True
            self.logger.debug(f"No value for '{param.name}' present, using default value.", 1)
        else:
            try:
                value = self.evaluator.parse_param_value(param.value, event, arf_args, level=0).value
                if value is None:
                    raise ValueError("None value not permitted for param.")
            except Exception as e:
                self.exception_handler.handle(e)
                self.logger.debug(f"Param evaluation for '{param.name}' failed, using default value.", 1)
                use_default = True
        if use_default:
            if param.value_default is not None:
                value = param.value_default
            else:
                raise ParamEvalError(f"Neither value present nor value_default defined for param {param.name}.")
        self.logger.debug(f"Final value for '{param.name}' is: '{value}'", 2)
        return value

    def __prompt_manual_value_on_err(self, param: ModuleParam, val: EvaluatedParam) -> str:
        self.logger.warn(f"Automatic evaluation failed for parameter '{param.name}'. Manual input required.")
        while not val:
            val = self.logger.prompt(f"Please provide a value for '{param.name}', type '?' for a description")
            if param.configurable and val == '?':
                self.logger.info(f"Description of param {param.name}: '{param.description}'")
        return val

    def __prompt_manual_value(self, arf_args: Namespace, automatic_value: Any, param: ModuleParam, val: Any) -> str:
        if param.configurable and arf_args.manual_mode:
            self.logger.info(f"Automatically evaluated value for param '{param.name}': '{automatic_value}'")
            val = self.logger.prompt(
                f"Please provide a value for the parameter '{param.name}', type '?' for a description or hit enter to accept the above value")
        if param.configurable and val == '?':
            self.logger.info(f"Description of param {param.name}: '{param.description}'")
            val = self.logger.prompt(
                f"Please provide a value for the parameter '{param.name}', or hit enter to accept the automatically detected value '{automatic_value}'")
        return val
