from dataclasses import dataclass


@dataclass
class CvssForVuln:
    cve: str
    score: float
    version: int
