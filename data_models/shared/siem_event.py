from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from bson import ObjectId

from config import ArfConfig
from data_models.shared import Host
from utils import CVEUtils, TimeUtils


@dataclass
class SiemEvent:
    src: Host
    dst: Host
    cves: list[str]
    timestamp: datetime
    all_fields: dict
    _id: ObjectId = field(default_factory=ObjectId)

    def __post_init__(self):
        if self.src is not None and isinstance(self.src, dict):
            self.src = Host(**self.src)
        if self.dst is not None and isinstance(self.dst, dict):
            self.dst = Host(**self.dst)

    def __str__(self) -> str:
        return f"SiemEvent(id={self.id}, src={self.src}, dst={self.dst}, cves={self.cves}, timestamp={self.timestamp})"

    @staticmethod
    def from_json(event: dict) -> Optional['SiemEvent']:
        return SiemEvent(src=Host(event.get('src_ip'), event.get('src_port')),
                         dst=Host(event.get('dest_ip'), event.get('dest_port')),
                         cves=SiemEvent.get_cves_from_json(
                             event.get('alert') or event.get('alert.metadata.cve{}') or event.get('alert.signature')),
                         timestamp=TimeUtils.get_timestamp(event.get('timestamp'), ArfConfig.SIEM_DATE_FORMAT),
                         all_fields=event)

    @staticmethod
    def get_cves_from_json(alert: dict) -> list[str]:
        if alert is None:
            return None
        if isinstance(alert, str):
            return list(map(CVEUtils.match_one_cve, [alert]))
        if isinstance(alert, list):
            return list(map(CVEUtils.match_one_cve, alert))
        if 'metadata' in alert and alert.get('metadata').get('cve') and len(alert.get('metadata').get('cve')) > 0:
            return list(map(CVEUtils.match_one_cve, alert.get('metadata').get('cve')))
        return CVEUtils.match_all_cves(alert.get('signature'))

    @property
    def id(self) -> ObjectId:
        return self._id
