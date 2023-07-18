from dataclasses import dataclass, field
from datetime import datetime

from bson import ObjectId

from data_models.shared import Host


@dataclass
class VulnVerification:
    host: Host
    timestamp: datetime
    cves: list[str]
    _id: ObjectId = field(default_factory=ObjectId)

    def __post_init__(self):
        if self.host is not None and isinstance(self.host, dict):
            self.host = Host(**self.host)
