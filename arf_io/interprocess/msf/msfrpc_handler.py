from arf_io.interprocess.subprocess_handler import SubprocessHandler
from arf_io.ui import ArfLogger


class MsfRpcServerHandler:

    def __init__(self, pwd: str, user: str, port: str, host: str) -> None:
        self.logger = ArfLogger.instance()
        self.subprocess = SubprocessHandler()
        self.start_msfrpcd(pwd, user, port, host)

    def start_msfrpcd(self, host: str, port: str, user: str, pwd: str) -> None:
        self.logger.info("Starting MSF RPC daemon and connecting...")
        self.subprocess.start("msfrpcd", ["-P", pwd, "-U", user, "-p", port, "-S", "-f", "-a", host])

    def terminate(self):
        self.subprocess.terminate_all()
