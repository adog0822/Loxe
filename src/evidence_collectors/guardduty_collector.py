"""GuardDuty evidence collector – detector status and security findings."""

from __future__ import annotations

from typing import Any

from src.aws_connectors.guardduty import GuardDutyConnector
from src.evidence_collectors.base import BaseEvidenceCollector, Evidence


class GuardDutyEvidenceCollector(BaseEvidenceCollector):
    source = "AWS_GuardDuty"

    def __init__(self) -> None:
        self.connector = GuardDutyConnector()

    def collect(self) -> list[Evidence]:
        raw = self.connector.collect_all()
        evidence: list[Evidence] = []

        evidence.append(self._collect_detector_status(raw))
        evidence.append(self._collect_findings_summary(raw))

        return evidence

    def _collect_detector_status(self, raw: dict[str, Any]) -> Evidence:
        detectors = [
            {
                "status": d.get("Status"),
                "service_role": d.get("ServiceRole"),
                "created_at": d.get("CreatedAt"),
                "updated_at": d.get("UpdatedAt"),
            }
            for d in raw.get("detectors", [])
        ]
        all_active = (
            all(d["status"] == "ENABLED" for d in detectors) if detectors else False
        )
        return self._make_evidence(
            evidence_type="detector_status",
            data={
                "detector_count": len(detectors),
                "all_active": all_active,
                "detectors": detectors,
            },
            controls=["CC7.1", "CC7.2"],
        )

    def _collect_findings_summary(self, raw: dict[str, Any]) -> Evidence:
        findings = raw.get("findings", [])
        severity_counts: dict[str, int] = {}
        summarized = []
        for f in findings:
            sev = str(f.get("Severity", "UNKNOWN"))
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            summarized.append(
                {
                    "id": f.get("Id"),
                    "type": f.get("Type"),
                    "severity": f.get("Severity"),
                    "title": f.get("Title"),
                    "description": f.get("Description"),
                    "created_at": f.get("CreatedAt"),
                    "updated_at": f.get("UpdatedAt"),
                }
            )
        return self._make_evidence(
            evidence_type="findings_summary",
            data={
                "total_findings": len(summarized),
                "severity_counts": severity_counts,
                "findings": summarized,
            },
            controls=["CC7.1", "CC7.2", "CC7.4"],
        )
