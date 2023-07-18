from enum import Enum


class ArfEnum(Enum):

    def __str__(self) -> str:
        return self.name

    @classmethod
    def is_member(cls, value: str) -> bool:
        return value in (e.value for e in cls)
