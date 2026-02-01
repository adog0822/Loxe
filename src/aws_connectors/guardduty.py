"""AWS GuardDuty connector – collects detectors and findings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.aws_connectors.base import BaseConnector


class GuardDutyConnector(BaseConnector):
    service_name = "guardduty"

    def list_detectors(self) -> list[str]:
        resp = self.client.list_detectors()
        return resp.get("DetectorIds", [])

    def get_detector(self, detector_id: str) -> dict[str, Any]:
        return self.client.get_detector(DetectorId=detector_id)

    def list_findings(self, detector_id: str, max_results: int = 50) -> list[str]:
        resp = self.client.list_findings(
            DetectorId=detector_id,
            MaxResults=max_results,
            SortCriteria={"AttributeName": "severity", "OrderBy": "DESC"},
        )
        return resp.get("FindingIds", [])

    def get_findings(
        self, detector_id: str, finding_ids: list[str]
    ) -> list[dict[str, Any]]:
        if not finding_ids:
            return []
        resp = self.client.get_findings(
            DetectorId=detector_id, FindingIds=finding_ids
        )
        return resp.get("Findings", [])

    def collect_all(self) -> dict[str, Any]:
        detector_ids = self.list_detectors()
        detectors = []
        all_findings: list[dict[str, Any]] = []

        for did in detector_ids:
            detectors.append(self.get_detector(did))
            finding_ids = self.list_findings(did)
            all_findings.extend(self.get_findings(did, finding_ids))

        return {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "detectors": detectors,
            "findings": all_findings,
        }
