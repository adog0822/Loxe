"""AWS Config connector – collects Config rules and compliance status."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.aws_connectors.base import BaseConnector


class ConfigConnector(BaseConnector):
    service_name = "config"

    def describe_config_rules(self) -> list[dict[str, Any]]:
        return self.paginate("describe_config_rules", "ConfigRules")

    def describe_compliance_by_config_rule(self) -> list[dict[str, Any]]:
        resp = self.client.describe_compliance_by_config_rule()
        return resp.get("ComplianceByConfigRules", [])

    def describe_configuration_recorders(self) -> list[dict[str, Any]]:
        resp = self.client.describe_configuration_recorders()
        return resp.get("ConfigurationRecorders", [])

    def describe_configuration_recorder_status(self) -> list[dict[str, Any]]:
        resp = self.client.describe_configuration_recorder_status()
        return resp.get("ConfigurationRecordersStatus", [])

    def collect_all(self) -> dict[str, Any]:
        return {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "config_rules": self.describe_config_rules(),
            "compliance": self.describe_compliance_by_config_rule(),
            "recorders": self.describe_configuration_recorders(),
            "recorder_status": self.describe_configuration_recorder_status(),
        }
