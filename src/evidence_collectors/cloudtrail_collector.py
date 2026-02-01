"""CloudTrail evidence collector – trail config, logging status, and security events."""

from __future__ import annotations

from typing import Any

from src.aws_connectors.cloudtrail import CloudTrailConnector
from src.evidence_collectors.base import BaseEvidenceCollector, Evidence


class CloudTrailEvidenceCollector(BaseEvidenceCollector):
    source = "AWS_CloudTrail"

    def __init__(self) -> None:
        self.connector = CloudTrailConnector()

    def collect(self) -> list[Evidence]:
        raw = self.connector.collect_all()
        evidence: list[Evidence] = []

        evidence.append(self._collect_trail_config(raw))
        evidence.append(self._collect_logging_status(raw))
        evidence.append(self._collect_security_events(raw))

        return evidence

    def _collect_trail_config(self, raw: dict[str, Any]) -> Evidence:
        trails = []
        for item in raw["trails"]:
            trail = item["trail"]
            trails.append(
                {
                    "name": trail.get("Name"),
                    "arn": trail.get("TrailARN"),
                    "is_multi_region": trail.get("IsMultiRegionTrail", False),
                    "log_file_validation": trail.get(
                        "LogFileValidationEnabled", False
                    ),
                    "s3_bucket": trail.get("S3BucketName"),
                    "kms_key_id": trail.get("KmsKeyId"),
                    "is_organization_trail": trail.get(
                        "IsOrganizationTrail", False
                    ),
                }
            )
        return self._make_evidence(
            evidence_type="trail_configuration",
            data={"trail_count": len(trails), "trails": trails},
            controls=["CC7.1", "CC7.2"],
        )

    def _collect_logging_status(self, raw: dict[str, Any]) -> Evidence:
        statuses = []
        for item in raw["trails"]:
            status = item["status"]
            statuses.append(
                {
                    "trail_arn": item["trail"].get("TrailARN"),
                    "is_logging": status.get("IsLogging", False),
                    "latest_delivery_time": str(
                        status.get("LatestDeliveryTime", "N/A")
                    ),
                    "latest_notification_time": str(
                        status.get("LatestNotificationTime", "N/A")
                    ),
                }
            )
        all_logging = all(s["is_logging"] for s in statuses) if statuses else False
        return self._make_evidence(
            evidence_type="logging_status",
            data={
                "all_trails_logging": all_logging,
                "statuses": statuses,
            },
            controls=["CC7.1", "CC7.2", "CC7.4"],
        )

    def _collect_security_events(self, raw: dict[str, Any]) -> Evidence:
        events = [
            {
                "event_id": e.get("EventId"),
                "event_name": e.get("EventName"),
                "event_time": str(e.get("EventTime", "")),
                "username": e.get("Username"),
            }
            for e in raw.get("recent_events", [])
        ]
        logins = [
            {
                "event_time": str(e.get("EventTime", "")),
                "username": e.get("Username"),
            }
            for e in raw.get("console_logins", [])
        ]
        return self._make_evidence(
            evidence_type="security_events",
            data={
                "recent_event_count": len(events),
                "recent_events": events,
                "console_login_count": len(logins),
                "console_logins": logins,
            },
            controls=["CC7.1", "CC7.2", "CC7.4"],
        )
