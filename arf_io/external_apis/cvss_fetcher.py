from typing import Optional

import requests

from arf_io.db import DbHandler
from arf_io.ui import ArfLogger
from config import ApiConfig
from data_models import CvssForVuln


class CvssFetcher:

    def __init__(self, db: DbHandler) -> None:
        self.logger = ArfLogger.instance()
        self.db = db

    def get_many_cvss_scores(self, cve_ids: [str]) -> [CvssForVuln]:
        if not isinstance(cve_ids, list):
            cve_ids = [cve_ids]
        return [self.get_one_cvss_score(cve_id) for cve_id in cve_ids]

    def get_one_cvss_score(self, cve_id: str) -> CvssForVuln:
        self.logger.debug(f"Querying CVSS score for CVE {cve_id}.")
        source = None
        cvss = self.db.get_cvss_score(cve_id)
        if cvss:
            source = "cache"
        else:
            # If the score is not found in the database, fetch it using the NVD API and store it in the DB
            cvss = self.__fetch_cvss_score_from_api(cve_id)
            if cvss:
                self.db.write_cvss_score(cvss)
                source = "NVD API"
        if cvss:
            self.logger.info(f"Retrieved CVSS score from {source}: {cvss.score} (CVSS v{cvss.version})")
        return cvss

    def __fetch_cvss_score_from_api(self, cve_id: str) -> Optional[CvssForVuln]:
        self.logger.debug(f"Using the NVD API to fetch the CVSS base score for ID {cve_id}", 1)
        if not cve_id:
            return None
        try:
            url = ApiConfig.CVSS_API_URL.format(ID=cve_id)
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            return self.__parse_score_and_version(cve=cve_id, data=data)
        except requests.exceptions.RequestException as e:
            self.logger.warn(f"Failed to fetch CVSS Score for ID {cve_id}: {e}")
            return None

    def __parse_score_and_version(self, cve: str, data: dict) -> Optional[CvssForVuln]:
        score, version = None, None

        if "result" in data and "CVE_Items" in data["result"] and len(data["result"]["CVE_Items"]) > 0:
            item = data["result"]["CVE_Items"][0]

            # check for the v3 score
            if "impact" in item and "baseMetricV3" in item["impact"] and "cvssV3" in item["impact"]["baseMetricV3"]:
                cvss_v3 = item["impact"]["baseMetricV3"]["cvssV3"]
                if "baseScore" in cvss_v3:
                    score = cvss_v3["baseScore"]
                    version = 3

            # check for the v2 score, if the v3 score is not found
            if score is None and "impact" in item and "baseMetricV2" in item["impact"] and "cvssV2" in item["impact"][
                "baseMetricV2"]:
                cvss_v2 = item["impact"]["baseMetricV2"]["cvssV2"]
                if "baseScore" in cvss_v2:
                    score = cvss_v2["baseScore"]
                    version = 2

        if score is not None and version is not None:
            self.logger.debug(f"Got CVSS v{version} score: {score}", 2)
            return CvssForVuln(cve=cve, score=score, version=version)
        else:
            self.logger.warn(f"Unable to parse CVSS score from API response. Continue without.")
            return None
