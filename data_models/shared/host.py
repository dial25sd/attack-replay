from dataclasses import dataclass

from utils import IPAddress, IpUtils


@dataclass
class Host:
    ip: IPAddress
    port: int

    def __post_init__(self):
        if isinstance(self.ip, str):
            self.ip = IpUtils.get_ip_addr(self.ip)

    def __str__(self) -> str:
        return f"Host({self.ip}:{self.port})"
