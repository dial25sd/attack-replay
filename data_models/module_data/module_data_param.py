from dataclasses import dataclass, field
from typing import Optional, Union

from arf_io.exceptions import ModuleDefinitionError
from utils import ArfEnum
from .module_data_result import ModuleResultCriterion
from .module_data_success import ModuleSuccessCriterion


# strategies to get a param value from given inputs
class ParamValueStrategy(ArfEnum):
    EXTRACT = "extract"  # extract a value using a regex
    ASSEMBLE = "assemble"  # construct a string from multiple inputs
    EXISTS = "exists"  # choose the first value that actually exists


# sources to get a param value from the specified sources
class ParamValueSource(ArfEnum):
    EVENT_DATA = "event_data"  # get a value from the SIEM event data
    SCANNER = "scanner"  # get a value using a PARAM_SCANNER module
    ARF_ARG = "arf_arg"  # get a value from the command line arguments
    RANDOM = "random"  # get a random value


@dataclass
class ModuleWithParamOverrides:
    name: str
    parameters: list['ModuleParam'] = field(default_factory=list)
    payload_parameters: list['ModuleParam'] = field(default_factory=list)
    success: list['ModuleSuccessCriterion'] = field(default_factory=list)
    result: ModuleResultCriterion = None

    def __post_init__(self):
        if self.parameters is not None and isinstance(self.parameters, dict):
            self.parameters = [ModuleParam(**param) for param in self.parameters]
        if self.success is not None and isinstance(self.success, dict):
            self.success = [ModuleSuccessCriterion(**crit) for crit in self.success]
        if self.result is not None and isinstance(self.result, dict):
            self.result = ModuleResultCriterion(**self.result)

    def __str__(self) -> str:
        return f"ModuleWithParamOverrides(name: {self.name}, parameters: #{len(self.parameters)}, success: #{len(self.success)})"


@dataclass
class ModuleParamValue:
    method: Union[ParamValueStrategy, ParamValueSource]
    argument: Union[str, int, None, ModuleWithParamOverrides]
    name: str = None
    input: Optional[Union['ModuleParamValue', list['ModuleParamValue']]] = None

    def __post_init__(self):
        if self.input and isinstance(self.input, list):
            self.input = [ModuleParamValue(**v) if isinstance(v, dict) else v for v in self.input]
        if self.input and isinstance(self.input, dict):
            self.input = ModuleParamValue(**self.input) if isinstance(self.input, dict) else self.input
        if not isinstance(self.argument, str) and not isinstance(self.argument, int) and self.argument is not None:
            self.argument = ModuleWithParamOverrides(
                **self.argument if isinstance(self.argument, dict) else self.argument)
        if ParamValueStrategy.is_member(self.method.lower() if isinstance(self.method, str) else self.method):
            self.method = ParamValueStrategy(self.method.lower() if isinstance(self.method, str) else self.method)
        elif ParamValueSource.is_member(self.method.lower()):
            self.method = ParamValueSource(self.method.lower())
        else:
            raise ModuleDefinitionError(f"Cannot parse Strategy or Source for value '{self.method}'")
        if self.input and isinstance(self.method, ParamValueSource):
            raise ModuleDefinitionError(f"ParamValue {self.name} of type {type(self.method)} cannot have value(s)!")


@dataclass
class ModuleParam:
    name: str
    description: Optional[str] = None
    value_default: Optional[str] = None
    value: Optional[ModuleParamValue] = None
    configurable: bool = True

    def __post_init__(self):
        if self.value is not None and isinstance(self.value, dict):
            self.value = ModuleParamValue(**self.value)

    def __str__(self) -> str:
        return f"ModuleParam(name: {self.name}, value_default: {self.value_default}, value: {self.value})"

    def validate(self) -> None:
        if self.value is None and self.value_default is None:
            raise ModuleDefinitionError(f"Either value or value_default of param '{self.name}' needs to be set.")


@dataclass
class EvaluatedParam:
    name: str
    value: any
