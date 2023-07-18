from argparse import Namespace
from typing import Optional, TYPE_CHECKING

from arf_io.exceptions import ParamEvalError
from arf_io.ui import ArfLogger
from data_models.module_data import EvaluatedParam, ModuleParamValue, ParamValueSource, ParamValueStrategy
from data_models.shared import SiemEvent
from utils import RandomUtils, RegexUtils

if TYPE_CHECKING:
    pass


class ParamEvaluator:

    def __init__(self, module_executor: 'ModuleExecutor'):
        self.logger = ArfLogger.instance()
        self.module_executor = module_executor

    def parse_param_value(self, param_val: ModuleParamValue, event: SiemEvent, arf_args: Namespace, level: int) -> \
            Optional[EvaluatedParam]:
        self.__log_param_parsing(param_val, level)

        if ParamValueStrategy.is_member(param_val.method.value.lower()):
            method = ParamValueStrategy(param_val.method.value.lower())
        else:
            method = ParamValueSource(param_val.method.value.lower())

        if isinstance(method, ParamValueStrategy):
            return self.__get_value_with_strategy(method, param_val, event, arf_args, level)
        elif isinstance(method, ParamValueSource):
            return self.__get_value_from_source(method, param_val, event, arf_args, level)
        raise AttributeError(f"No such param method: {method}")

    def __get_value_with_strategy(self, strategy: ParamValueStrategy, param_val: ModuleParamValue, event: SiemEvent,
                                  arf_args: Namespace, level: int) -> EvaluatedParam:
        if strategy == ParamValueStrategy.EXTRACT:
            return self.__eval_param_value_extract(param_val=param_val, arf_args=arf_args, event=event, level=level)
        elif strategy == ParamValueStrategy.ASSEMBLE:
            return self.__eval_param_value_assemble(param_val=param_val, arf_args=arf_args, event=event, level=level)
        elif strategy == ParamValueStrategy.EXISTS:
            return self.__eval_param_value_exists(param_val=param_val, arf_args=arf_args, event=event, level=level)
        raise ParamEvalError(
            f"Unknown Param Eval strategy: '{param_val.method}'. Supported values are: '{','.join(list(ParamValueStrategy))}'")

    def __get_value_from_source(self, source: ParamValueSource, param_val: ModuleParamValue, event: SiemEvent,
                                arf_args: Namespace, level: int) -> EvaluatedParam:
        if source == ParamValueSource.EVENT_DATA:
            return self.__eval_param_from_event_data(param_val=param_val, event=event, level=level)
        elif source == ParamValueSource.SCANNER:
            return self.__eval_param_from_scanner(param_val=param_val, event=event, arf_args=arf_args, level=level)
        elif source == ParamValueSource.ARF_ARG:
            return self.__eval_param_from_arf_param(param_val=param_val, arf_args=arf_args, level=level)
        elif source == ParamValueSource.RANDOM:
            return self.__eval_param_from_random(param_val=param_val, level=level)
        raise ParamEvalError(
            f"Unknown Param Eval source: '{param_val.method}'. Supported values are: '{','.join(list(ParamValueSource))}'")

    def __eval_param_value_extract(self, param_val: ModuleParamValue, arf_args: Namespace, event: SiemEvent,
                                   level: int) -> EvaluatedParam:
        extraction_str = self.parse_param_value(param_val.input, event, arf_args=arf_args, level=level + 1).value
        try:
            value = RegexUtils.extract_first_group(param_val.argument, extraction_str)
        except (AttributeError, IndexError) as e:
            raise ParamEvalError(f"Cannot extract param value '{param_val.name}' with regex.") from e
        return EvaluatedParam(name=param_val.name, value=value.strip())

    def __eval_param_value_assemble(self, param_val: ModuleParamValue, arf_args: Namespace, event: SiemEvent,
                                    level: int) -> EvaluatedParam:
        evaluated_values = [self.parse_param_value(value, event, arf_args, level=level + 1) for value in
                            param_val.input]
        replacements_dict = {v.name: v.value for v in evaluated_values}
        value = param_val.argument.format(**replacements_dict)
        return EvaluatedParam(name=param_val.name, value=value)

    def __eval_param_value_exists(self, param_val: ModuleParamValue, arf_args: Namespace, event: SiemEvent,
                                  level: int) -> EvaluatedParam:
        evaluated = None
        for value in param_val.input:
            try:
                evaluated = self.parse_param_value(value, event, arf_args, level=level + 1).value
                if evaluated is not None:
                    break
            except ParamEvalError:
                self.logger.debug(f"EXISTS: Unable to eval param '{value.name}', trying next one in list.", 2)
                pass
        if evaluated is None:
            evaluated = param_val.argument
        if evaluated is None or evaluated == '':
            raise ParamEvalError("Cannot eval param using EXISTS strategy.")
        return EvaluatedParam(name=param_val.name, value=evaluated)

    def __eval_param_from_arf_param(self, param_val: ModuleParamValue, arf_args: Namespace,
                                    level: int) -> EvaluatedParam:
        if param_val.argument not in arf_args:
            raise ParamEvalError(f"Unknown key '{param_val.argument}' for param {param_val.name} not found in ARF args")
        return EvaluatedParam(name=param_val.name, value=str(vars(arf_args).get(param_val.argument)))

    def __eval_param_from_random(self, param_val: ModuleParamValue, level: int) -> EvaluatedParam:
        if param_val.argument == 'port':
            value = RandomUtils.get_random_port()
        elif param_val.argument == 'password':
            value = RandomUtils.get_random_password()
        else:
            raise ParamEvalError(
                f"Can't eval param '{param_val.name}' using strategy 'random' with unknown arg: '{param_val.argument}'.")
        return EvaluatedParam(name=param_val.name, value=value)

    def __eval_param_from_event_data(self, param_val: ModuleParamValue, event: SiemEvent, level: int) -> EvaluatedParam:
        keys = param_val.argument.split('.')

        def get_nested_value(data: dict, remaining_keys: list) -> dict:
            if len(remaining_keys) == 0:
                return data
            key = remaining_keys.pop(0)
            if key not in data:
                raise ParamEvalError(f"Unknown key '{key}' for param {param_val.name} not found in event data")
            return get_nested_value(data[key], remaining_keys)

        value = event.all_fields.get(param_val.argument) or get_nested_value(event.all_fields, keys)
        return EvaluatedParam(name=param_val.name, value=value)

    def __eval_param_from_scanner(self, param_val: ModuleParamValue, event: SiemEvent, arf_args: Namespace,
                                  level: int) -> EvaluatedParam:
        value = self.module_executor.exec_and_resolve(module=param_val.argument, event=event, arf_args=arf_args)
        return EvaluatedParam(name=param_val.name, value=value)

    def __log_param_parsing(self, param_val: ModuleParamValue, level: int) -> None:
        if param_val.name is not None:
            self.logger.debug(
                f"Eval param '{param_val.name}' with method '{param_val.method}' and args '{param_val.argument}'",
                level + 1)
        else:
            self.logger.debug(f"Eval param with method '{param_val.method}' and args '{param_val.argument}'", level + 1)
