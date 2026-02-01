"""AWS CloudTrail connector – collects trail configuration and recent events."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from src.aws_connectors.base import BaseConnector


class CloudTrailConnector(BaseConnector):
    service_name = "cloudtrail"

    def describe_trails(self) -> list[dict[str, Any]]:
        resp = self.client.describe_trails()
        return resp.get("trailList", [])

    def get_trail_status(self, trail_arn: str) -> dict[str, Any]:
        return self.client.get_trail_status(Name=trail_arn)

    def lookup_events(
        self,
        days_back: int = 90,
        max_results: int = 50,
        event_name: str | None = None,
    ) -> list[dict[str, Any]]:
        kwargs: dict[str, Any] = {
            "StartTime": datetime.now(timezone.utc) - timedelta(days=days_back),
            "EndTime": datetime.now(timezone.utc),
            "MaxResults": max_results,
        }
        if event_name:
            kwargs["LookupAttributes"] = [
                {"AttributeKey": "EventName", "AttributeValue": event_name}
            ]
        resp = self.client.lookup_events(**kwargs)
        return resp.get("Events", [])

    def collect_all(self) -> dict[str, Any]:
        trails = self.describe_trails()
        trail_statuses = []
        for trail in trails:
            arn = trail.get("TrailARN", "")
            status = self.get_trail_status(arn)
            trail_statuses.append({"trail": trail, "status": status})

        # Collect security-relevant events
        security_events = self.lookup_events(
            days_back=90, max_results=50
        )
        console_logins = self.lookup_events(
            days_back=30, max_results=50, event_name="ConsoleLogin"
        )

        return {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "trails": trail_statuses,
            "recent_events": security_events,
            "console_logins": console_logins,
        }
