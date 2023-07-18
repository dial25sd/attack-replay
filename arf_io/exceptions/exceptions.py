class ArfArgumentValidationError(Exception):
    pass


class VerificationPermissionError(Exception):
    pass


class ModuleLoadError(Exception):
    pass


class ModuleExecutionError(Exception):
    pass


class ParamEvalError(Exception):
    pass


class ModuleDefinitionError(Exception):
    pass


class ModuleTimeoutError(Exception):
    pass


class ArfReportError(Exception):
    pass


class ArfDbError(Exception):
    pass


class MsfRpcConnectionError(Exception):
    pass


class ArfDockerConnectionError(Exception):
    pass
