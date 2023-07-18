from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from typing import Union

from arf_io.exceptions import ArfArgumentValidationError

IPNetwork = Union[IPv4Network, IPv6Network]
IPAddress = Union[IPv4Address, IPv6Address]


class IpUtils:

    @staticmethod
    def validate_ip_addr(ip: str) -> IPAddress:
        try:
            return ip_address(ip)
        except ValueError as e:
            raise ArfArgumentValidationError("not a valid IP address") from e

    @staticmethod
    def validate_subnet(subnet: str) -> IPNetwork:
        try:
            return ip_network(subnet)
        except ValueError as e:
            raise ArfArgumentValidationError("not a valid IP network") from e

    @staticmethod
    def get_ip_addr(addr: str) -> IPAddress:
        return ip_address(addr)

    @staticmethod
    def get_subnet(subnet: str) -> IPNetwork:
        return ip_network(subnet)

    @staticmethod
    def is_in_subnet(ip: IPAddress, subnet: IPNetwork):
        return ip in subnet
