"""AWS IAM connector – collects users, roles, policies, MFA, and access keys."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.aws_connectors.base import BaseConnector


class IAMConnector(BaseConnector):
    service_name = "iam"

    def list_users(self) -> list[dict[str, Any]]:
        return self.paginate("list_users", "Users")

    def list_roles(self) -> list[dict[str, Any]]:
        return self.paginate("list_roles", "Roles")

    def list_policies(self, scope: str = "Local") -> list[dict[str, Any]]:
        return self.paginate("list_policies", "Policies", Scope=scope)

    def list_mfa_devices(self, username: str) -> list[dict[str, Any]]:
        resp = self.client.list_mfa_devices(UserName=username)
        return resp.get("MFADevices", [])

    def list_access_keys(self, username: str) -> list[dict[str, Any]]:
        resp = self.client.list_access_keys(UserName=username)
        return resp.get("AccessKeyMetadata", [])

    def get_account_password_policy(self) -> dict[str, Any]:
        try:
            resp = self.client.get_account_password_policy()
            return resp.get("PasswordPolicy", {})
        except self.client.exceptions.NoSuchEntityException:
            return {}

    def get_credential_report(self) -> list[dict[str, str]]:
        """Generate and parse the IAM credential report CSV."""
        import csv
        import io
        import time

        # Generating may take a moment; poll until complete.
        for _ in range(10):
            state = self.client.generate_credential_report().get("State")
            if state == "COMPLETE":
                break
            time.sleep(1)

        resp = self.client.get_credential_report()
        content = resp["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        return list(reader)

    def collect_all(self) -> dict[str, Any]:
        """Collect all IAM evidence in one call."""
        users = self.list_users()
        enriched_users = []
        for user in users:
            username = user["UserName"]
            enriched_users.append(
                {
                    **user,
                    "MFADevices": self.list_mfa_devices(username),
                    "AccessKeys": self.list_access_keys(username),
                }
            )

        return {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "users": enriched_users,
            "roles": self.list_roles(),
            "policies": self.list_policies(),
            "password_policy": self.get_account_password_policy(),
            "credential_report": self.get_credential_report(),
        }
