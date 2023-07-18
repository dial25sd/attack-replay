import re
from typing import AnyStr


class RegexUtils:

    @staticmethod
    def extract_first_group(regex: str, data: str) -> AnyStr:
        match = RegexUtils.search(regex, data)
        if not match:
            raise AttributeError("No match found, cannot extract group.")
        return match.group(1)

    @staticmethod
    def search(regex: str, data: str):
        return re.search(regex, data)

    @staticmethod
    def findall(regex: str, data: str):
        return re.findall(regex, data)
