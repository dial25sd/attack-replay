import concurrent.futures
import time
from typing import Any

from requests.exceptions import ConnectionError
from urllib3.exceptions import MaxRetryError, NewConnectionError

from arf_io.exceptions import ExceptionHandler, ModuleExecutionError, ModuleLoadError, ModuleTimeoutError, \
    MsfRpcConnectionError
from arf_io.ui import ArfLogger
from config import ArfConfig, MsfConfig
from data_models.exec_data import ModuleExecDetails, MsfSession
from data_models.module_data import ModuleClass, MsfModuleExecMode
from pymetasploit3.msfconsole import MsfRpcConsole
from pymetasploit3.msfrpc import MsfAuthError, MsfModule, MsfRpcClient, MsfRpcError


class MsfHandler:
    command_to_run_on_session = ["uname -a", "whoami", "ip a", "ipconfig"]

    def __init__(self, host, port, user, pwd):
        self.logger = ArfLogger.instance()
        self.exc_handler = ExceptionHandler()
        self.msfrpc_client = self.get_msfrpc_client(host=host, port=port, user=user, pwd=pwd)
        if self.msfrpc_client is None:
            raise MsfRpcConnectionError('Cannot connect to MSF RPC.')

    def get_msfrpc_client(self, host, port, user, pwd):
        current_tries = 0
        msf_client = None
        while current_tries < MsfConfig.CONN_MAX_TRIES:
            if current_tries > 0:
                self.logger.debug(f"Retrying in {MsfConfig.CONN_TIME_SLEEP} secs...", 1)
            time.sleep(MsfConfig.CONN_TIME_SLEEP)
            current_tries += 1
            self.logger.debug("Trying to connect to MSF RPC server...")
            msf_client = None
            try:
                msf_client = MsfRpcClient(password=pwd, port=port, server=host, username=user, ssl=False)
                self.logger.success(f"Successfully connected to MSF RPC at {host}:{port}.")
                msf_console = MsfRpcConsole(msf_client, cb=MsfHandler.read_output)
                break
            except (ConnectionRefusedError, NewConnectionError, MaxRetryError, ConnectionError) as e:
                self.logger.debug(f"Connection to MSF RPC at {host}:{port} couldn't be established (yet).", 1)
            except MsfAuthError as e:
                self.logger.warn(f"MSF RPC Authentication error: {e}. Please check the credentials.")
                break
            except MsfRpcError as e:
                self.logger.warn(f"Error while logging in to MSF RPC: {e}")
        return msf_client

    @staticmethod
    def read_output(data):
        ArfLogger.instance().debug(f"MSF main console received data: {data}")

    def get_module_by_path(self, complete_module_path: str) -> MsfModule:
        try:
            module_type = complete_module_path.split('/')[0]
            module_path = '/'.join(complete_module_path.split('/')[1:])
            self.logger.debug(f"loading module '{module_path}' of type '{module_type}'", 1)
            return self.msfrpc_client.modules.use(module_type, module_path)
        except Exception as e:
            raise ModuleLoadError(f"Unable to load MSF module '{complete_module_path}': {e}") from e

    def set_msf_module_param(self, module: MsfModule, param_name: str, param_val: Any) -> None:
        if param_name != 'PAYLOAD':
            try:
                module[param_name] = param_val
            except KeyError as e:
                self.exc_handler.handle(e,
                                        msg=f"Unable to set value for param {param_name} for MSF module '{module.modulename}': check whether a param with this name actually exists for this module.")

    def terminate(self) -> None:
        self.msfrpc_client.logout()
        del self.msfrpc_client

    def check_for_missing_param_values(self, module_path: str, module: MsfModule) -> None:
        if len(module.missing_required) > 0:
            self.logger.warn(f"Module {module_path} requires these parameters: {module.missing_required}")

    def exec_module(self, module: MsfModule, module_class: ModuleClass, exec_mode: MsfModuleExecMode, payload=None,
                    timeout_secs=None) -> ModuleExecDetails:
        session = None
        if timeout_secs / 2 > ArfConfig.MAX_SESSION_TIMEOUT_SECS:
            session_timeout = ArfConfig.MAX_SESSION_TIMEOUT_SECS
            exec_timeout = timeout_secs - session_timeout
        else:
            exec_timeout = session_timeout = timeout_secs / 2
        output = self.__exec_module_with_timeout(module=module, payload=payload, exec_mode=exec_mode,
                                                 timeout=exec_timeout)
        sessions = self.msfrpc_client.sessions.list
        self.logger.debug(f"Received module output: {output}", 1)
        gathered_info = None
        if module_class is ModuleClass.EXPLOIT:
            self.logger.debug(f"Current sessions: {sessions}", 1)
            session = self.__check_for_session(module.modulename, timeout=session_timeout)
            if session:
                gathered_info = self.__exec_info_gathering(session.id)
        return ModuleExecDetails(output=output, session=session, gathered_info=gathered_info)

    def __exec_module_with_timeout(self, module, exec_mode: MsfModuleExecMode, timeout, payload=None):
        cid = self.msfrpc_client.consoles.console().cid
        self.logger.info(f"Module is being executed using MsfConsole {cid} and a timeout of {timeout} secs.")

        def module_runner():
            try:
                if exec_mode is MsfModuleExecMode.CHECK:
                    return self.msfrpc_client.consoles.console(cid).exec_check_with_output(module)
                elif exec_mode is MsfModuleExecMode.RUN:
                    return self.msfrpc_client.consoles.console(cid).run_module_with_output(module, payload=payload)
                else:
                    raise ModuleExecutionError(f"Unknown or unsupported exec mode for MSF module: {exec_mode}")
            except Exception as e:
                raise ModuleExecutionError(f"Cannot execute MSF module: {e}") from e

        output = None
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(module_runner)
                output = future.result(timeout)
        except concurrent.futures.TimeoutError as e:
            raise ModuleTimeoutError(f"Module execution exceeded the threshold of {timeout} seconds") from e
        if output is None:
            raise ModuleExecutionError("Unable to execute exploit: output is empty")
        else:
            self.logger.info("Exploit has been run without errors.")
        return output

    def __check_for_session(self, module_name, timeout):
        exploit_path = f"exploit/{module_name}"
        initial_sessions = self.__get_sessions()
        session_by_this_exploit = self.__get_session_of_module(exploit_path=exploit_path, sessions=initial_sessions)
        if session_by_this_exploit:
            return session_by_this_exploit

        self.logger.debug(f"Waiting for {timeout} secs for a new session to be created...")
        start_time = time.time()
        while True:
            time.sleep(MsfConfig.SESS_TIME_SLEEP)
            current_sessions = self.__get_sessions()
            new_sessions = list(set(current_sessions) - set(initial_sessions))

            if new_sessions:
                self.logger.debug(f"New session(s) created: {', '.join(map(str, new_sessions))}", 1)
                session_by_this_exploit = self.__get_session_of_module(exploit_path, new_sessions)
                return session_by_this_exploit
            elif time.time() - start_time >= timeout:
                self.logger.debug("No new session created. Timeout reached.", 1)
                break
            else:
                self.logger.debug("No new session created yet. Still waiting...", 1)
        return None

    def __get_session_of_module(self, exploit_path, sessions) -> MsfSession:
        all_session_by_this_exploit = []
        for id, session in sessions.items():
            if session.get('via_exploit') == exploit_path:
                all_session_by_this_exploit.append(MsfSession(id, session))
        current_session = all_session_by_this_exploit[-1] if all_session_by_this_exploit else None
        if current_session:
            self.logger.info(
                f"Exploit successful. Session created by this module: {{id: {current_session.id}, type: {current_session.session.get('type')}}}")
        return current_session

    def __get_sessions(self):
        return self.msfrpc_client.sessions.list  # return [session for session in sess_dict.values()]

    def __exec_info_gathering(self, session_id):
        self.logger.info("Gathering more infos about host using the established session")
        gathered_info = {}
        for cmd in self.command_to_run_on_session:
            output = self.msfrpc_client.sessions.session(session_id).run_with_output(cmd)
            gathered_info.update({cmd: output})
            self.logger.debug(f"Executing command '{cmd}': '{output}'", 1)
        return gathered_info
