from dataclasses import asdict
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Any


class Serializer:

    @staticmethod
    def serialize_dataclass(obj: Any):
        if obj is None:
            return Serializer.__serialize_all_types(obj)
        return Serializer.__serialize_all_types(asdict(obj))

    @staticmethod
    def serialize_dataclass_list(obj: list):
        if obj is None:
            return Serializer.__serialize_all_types(obj)
        return [Serializer.__serialize_all_types(asdict(x)) for x in obj]

    @staticmethod
    def __serialize_all_types(obj: Any) -> Any:
        if isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, dict):
            return {k: Serializer.__serialize_all_types(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [Serializer.__serialize_all_types(x) for x in obj]
        elif isinstance(obj, (IPv4Network, IPv6Network, IPv4Address, IPv6Address)):
            return str(obj)
        else:
            return obj
