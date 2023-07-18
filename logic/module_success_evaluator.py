from arf_io.ui import ArfLogger
from data_models.exec_data import ModuleExecData, ModuleExecDetails
from data_models.module_data import ModuleSuccessCriterion, ModuleSuccessStrategy
from utils import RegexUtils


class ModuleSuccessEvaluator:

    def __init__(self):
        self.logger = ArfLogger.instance()
        self.strategy_map = {ModuleSuccessStrategy.OUTPUT: self.__handle_output_strategy,
                             ModuleSuccessStrategy.SESSION: self.__handle_session_strategy,
                             ModuleSuccessStrategy.EXIT_CODE: self.__handle_exit_code_strategy,
                             ModuleSuccessStrategy.FALLBACK: self.__handle_fallback_strategy}

    def eval_module_success(self, exec_data: ModuleExecData, exec_result: ModuleExecDetails) -> ModuleSuccessCriterion:
        all_criteria = exec_data.overridden_success + exec_data.module_data.success
        self.logger.info(f"Evaluating success of module using {len(all_criteria)} criteria.")
        for criterion in all_criteria:
            self.logger.debug(
                f"Check using strategy '{criterion.strategy}', argument '{criterion.argument}' and conclusion '{criterion.conclusion}'",
                1)
            strategy_handler = self.strategy_map.get(criterion.strategy)
            if strategy_handler:
                res = strategy_handler(criterion, exec_result)
                if res is not None:
                    return res

    @staticmethod
    def __handle_output_strategy(criterion, exec_result: ModuleExecDetails) -> ModuleSuccessCriterion:
        if RegexUtils.search(criterion.argument, exec_result.output):
            return criterion

    @staticmethod
    def __handle_session_strategy(criterion, exec_result: ModuleExecDetails) -> ModuleSuccessCriterion:
        if exec_result.session is not None:
            return criterion

    @staticmethod
    def __handle_exit_code_strategy(criterion, exec_result: ModuleExecDetails) -> ModuleSuccessCriterion:
        if exec_result.exit_code == criterion.argument:
            return criterion

    @staticmethod
    def __handle_fallback_strategy(criterion, exec_result: ModuleExecDetails) -> ModuleSuccessCriterion:
        return criterion
