"""AWS CloudWatch connector – collects alarms and log group metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.aws_connectors.base import BaseConnector


class CloudWatchConnector(BaseConnector):
    service_name = "cloudwatch"

    def describe_alarms(self) -> list[dict[str, Any]]:
        return self.paginate("describe_alarms", "MetricAlarms")

    def collect_all(self) -> dict[str, Any]:
        alarms = self.describe_alarms()
        return {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "alarms": alarms,
        }


class CloudWatchLogsConnector(BaseConnector):
    service_name = "logs"

    def describe_log_groups(self) -> list[dict[str, Any]]:
        return self.paginate("describe_log_groups", "logGroups")

    def collect_all(self) -> dict[str, Any]:
        log_groups = self.describe_log_groups()
        return {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "log_groups": log_groups,
        }
