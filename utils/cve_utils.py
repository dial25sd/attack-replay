from typing import Optional

from .regex_utils import RegexUtils


class CVEUtils:
    regex = '((?:19|20)\d{2}(?:-|_)\d{4,})'

    @staticmethod
    def match_one_cve(cve_str: str) -> Optional[str]:
        try:
            match = RegexUtils.extract_first_group(CVEUtils.regex, cve_str)
            return CVEUtils.sanitize_cve(match)
        except (AttributeError, IndexError):
            return None

    @staticmethod
    def match_all_cves(cve_str: str) -> list[str]:
        return list(map(CVEUtils.sanitize_cve, RegexUtils.findall(CVEUtils.regex, cve_str)))

    @staticmethod
    def sanitize_cve(cve_str: str) -> Optional[str]:
        if not cve_str or not isinstance(cve_str, str):
            return None
        return cve_str.replace("_", "-")
