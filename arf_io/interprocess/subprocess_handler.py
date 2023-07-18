import subprocess

from arf_io.ui import ArfLogger


class SubprocessHandler:

    def __init__(self) -> None:
        self.logger = ArfLogger.instance()
        self.subprocesses = []

    def start(self, command: str, params: list[str]) -> subprocess.Popen:
        args = [command] + params
        self.logger.debug(f"Starting subprocess: {args}", 1)
        proc = subprocess.Popen(args, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
        self.subprocesses.append(proc)
        return proc

    def terminate_all(self) -> None:
        for process in self.subprocesses:
            process.kill()
            self.subprocesses.remove(process)
