from argparse import Namespace
from typing import Any, AnyStr, Optional

from arf_io.exceptions import ExceptionHandler, ModuleExecutionError, ParamEvalError, VerificationPermissionError
from arf_io.interprocess import DockerHandler, MsfHandler
from arf_io.modules import ArfModuleAdapter, MsfModuleAdapter
from arf_io.ui import ArfLogger
from data_models.exec_data import ModuleExecData, ModuleExecDetails
from data_models.module_data import ModuleClass, ModuleResultStrategy, ModuleSuccessCriterion, ModuleSuccessStrategy, \
    ModuleType, ModuleWithParamOverrides
from data_models.shared import SiemEvent
from utils import IPAddress, IPNetwork, IpUtils, RegexUtils
from .module_repo_cache import ModuleRepoCache
from .module_success_evaluator import ModuleSuccessEvaluator
from .param_handler import ParamHandler


class ModuleExecutor:

    def __init__(self, module_cache: ModuleRepoCache, internal_subnets: list[IPNetwork], msf_handler: MsfHandler,
                 docker_handler: DockerHandler, timeout: int):
        self.logger = ArfLogger.instance()
        self.internal_subnets = internal_subnets
        self.timeout = timeout
        self.success_evaluator = ModuleSuccessEvaluator()
        self.arf_module_handler = ArfModuleAdapter(docker_handler=docker_handler)
        self.msf_module_handler = MsfModuleAdapter(msf_handler=msf_handler)
        self.module_cache = module_cache
        self.exception_handler = ExceptionHandler()
        self.param_handler = ParamHandler(module_executor=self)

    def exec_and_evaluate(self, exec_data: ModuleExecData, event: SiemEvent, arf_args: Namespace) -> ModuleExecDetails:
        self.logger.success(f"Now execute&evaluate'ing module '{exec_data.module_data.name}'...")
        output, matching_success_criterion = None, None
        module_exec_success = True
        exec_details = ModuleExecDetails()
        try:
            self.__check_for_permission(event.dst.ip)
            exec_details = self.__exec_module(exec_data=exec_data, arf_args=arf_args, event=event)
            matching_success_criterion = self.__eval_success(exec_data, exec_details)
            exec_details.module_success = matching_success_criterion.conclusion
        except Exception as e:
            output = self.__handle_exception(e)
            module_exec_success = False
        exec_details.module_exec_success = False if matching_success_criterion is None else module_exec_success
        exec_details.output = output if output is not None else exec_details.output
        exec_details.module_name = exec_data.module_data.name
        exec_details.module_source = exec_data.module_data.source
        exec_details.matching_success_criterion = matching_success_criterion
        return exec_details

    def exec_and_resolve(self, module: ModuleWithParamOverrides, event: SiemEvent, arf_args: Namespace) -> AnyStr:
        self.logger.success(f"Now execute&resolving param value using module '{module.name}'...")
        exec_data = self.module_cache.get_matching_exec_data(module_class=ModuleClass.PARAM_SCANNER,
                                                             modules_with_override=[module], event_id=str(event.id))
        exec_details = ModuleExecDetails()
        if len(exec_data) != 1:
            raise ParamEvalError(f"More or less than 1 matching module for param scanner '{module.name}'")
        else:
            exec_data = exec_data[0]
        try:
            exec_details = self.__exec_module(exec_data=exec_data, arf_args=arf_args, event=event)
        except Exception as e:
            exec_details.output = self.__handle_exception(e)
        return self.__extract_result(exec_data=exec_data, exec_details=exec_details)

    def cleanup_on_exit(self) -> None:
        self.arf_module_handler.cleanup_on_exit()

    def __eval_success(self, exec_data: ModuleExecData, exec_details: ModuleExecDetails) -> ModuleSuccessCriterion:
        matching_criterion = self.success_evaluator.eval_module_success(exec_data, exec_details)
        if not matching_criterion:
            raise ModuleExecutionError("No matching criterion found. Cannot eval success of module.")
        elif matching_criterion.conclusion:
            self.logger.success("Module has been executed: SUCCESS.")
        else:
            self.logger.info("Module has been executed: NO SUCCESS.")
        return matching_criterion

    def __extract_result(self, exec_data: ModuleExecData, exec_details: ModuleExecDetails) -> Optional[Any]:
        module = exec_data.module_data
        strategy = exec_data.overridden_result.strategy if exec_data.overridden_result else module.result.strategy
        try:
            self.logger.debug(f"Getting result by strategy '{strategy}'", 1)
            result = self.__get_result_by_strategy(strategy=strategy, exec_data=exec_data, exec_details=exec_details)
            if result is not None:
                self.logger.success(f"Param value has successfully been extracted using scanner module: '{result}'")
            else:
                self.logger.info("Module has been executed: NO SUCCESS.")
            return result
        except Exception as e:
            raise ParamEvalError(f"Cannot get result from module '{module.name}' with strategy {strategy}.") from e

    def __get_result_by_strategy(self, strategy: ModuleResultStrategy, exec_data: ModuleExecData,
                                 exec_details: ModuleExecDetails):
        module = exec_data.module_data
        if strategy is ModuleResultStrategy.EXTRACT:
            return RegexUtils.extract_first_group(regex=module.result.argument, data=exec_details.output)
        elif strategy is ModuleResultStrategy.SUCCESS:
            conclusion = self.__eval_success(exec_data, exec_details).conclusion
            arguments = [
                exec_data.overridden_result.argument] if exec_data.overridden_result else module.result.argument
            if not arguments or arguments[0] is None:
                return conclusion
            elif conclusion and arguments:
                return arguments[0]
            elif not conclusion and len(arguments) > 1:
                return arguments[1]
        return None

    def __exec_module(self, exec_data: ModuleExecData, arf_args: Namespace, event: SiemEvent) -> ModuleExecDetails:
        module = exec_data.module_data
        try:
            self.logger.info("Configuring module...")
            param_dict = self.param_handler.get_all_param_values(arf_args, event, module.parameters,
                                                                 exec_data.overridden_params)
            if module.module_type is ModuleType.MSF:
                payload_param_dict = self.param_handler.get_all_param_values(arf_args, event, module.payload_parameters,
                                                                             exec_data.overridden_payload_params)
                exec_res = self.msf_module_handler.exec_module(module, self.timeout, param_dict=param_dict,
                                                               payload_param_dict=payload_param_dict)
            elif module.module_type is ModuleType.STANDALONE:
                use_exit_code_for_success = ModuleSuccessStrategy.EXIT_CODE.value in exec_data.module_data.success
                exec_res = self.arf_module_handler.exec_module(module, self.timeout, param_dict=param_dict,
                                                               use_exit_code_for_success=use_exit_code_for_success)
            else:
                raise ModuleExecutionError(f"Cannot execute unknown module type: '{module.module_type}'")
        except ParamEvalError as e:
            raise ModuleExecutionError(f"Cannot exec module '{module.name}': param evaluation has failed: '{e}'") from e
        return exec_res

    def __check_for_permission(self, target_ip: IPAddress) -> None:
        is_in_internal_subnets = any(IpUtils.is_in_subnet(target_ip, net) for net in self.internal_subnets)
        if not is_in_internal_subnets:
            raise VerificationPermissionError(
                f"Target IP ({target_ip}) is NOT in internal subnet(s): ({self.internal_subnets})")
        self.logger.debug(f"Target IP {target_ip} can be tested since it is considered an internal subnet.", 1, )

    def __handle_exception(self, e: Exception) -> str:
        output = f"Error during Module execution: {e}"
        self.exception_handler.handle(e, msg=output)
        return output
