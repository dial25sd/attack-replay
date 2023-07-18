from datetime import datetime
from typing import Optional


class TimeUtils:

    @staticmethod
    def get_secs_between_timestamps(timestamp1: datetime, timestamp2: datetime) -> float:
        diff = timestamp1 - timestamp2
        return abs(diff.total_seconds())

    @staticmethod
    def get_timestamp(timestamp_str, format_str: str) -> Optional[datetime]:
        try:
            return datetime.strptime(timestamp_str, format_str)
        except:
            return None
