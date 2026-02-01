"""IAM evidence collector – transforms raw IAM data into SOC 2 evidence items."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any

from src.aws_connectors.iam import IAMConnector
from src.evidence_collectors.base import BaseEvidenceCollector, Evidence


class IAMEvidenceCollector(BaseEvidenceCollector):
    source = "AWS_IAM"

    def __init__(self) -> None:
        self.connector = IAMConnector()

    def collect(self) -> list[Evidence]:
        raw = self.connector.collect_all()
        evidence: list[Evidence] = []

        evidence.append(self._collect_user_inventory(raw))
        evidence.append(self._collect_mfa_status(raw))
        evidence.append(self._collect_password_policy(raw))
        evidence.append(self._collect_access_key_rotation(raw))
        evidence.append(self._collect_role_inventory(raw))
        evidence.append(self._collect_policy_inventory(raw))

        return evidence

    def _collect_user_inventory(self, raw: dict[str, Any]) -> Evidence:
        users = [
            {
                "username": u["UserName"],
                "user_id": u["UserId"],
                "arn": u["Arn"],
                "created": _isoformat(u.get("CreateDate")),
                "password_last_used": _isoformat(u.get("PasswordLastUsed")),
            }
            for u in raw["users"]
        ]
        return self._make_evidence(
            evidence_type="user_inventory",
            data={"user_count": len(users), "users": users},
            controls=["CC6.1", "CC6.2", "CC6.3"],
        )

    def _collect_mfa_status(self, raw: dict[str, Any]) -> Evidence:
        users_mfa = []
        for u in raw["users"]:
            mfa_devices = u.get("MFADevices", [])
            users_mfa.append(
                {
                    "username": u["UserName"],
                    "mfa_enabled": len(mfa_devices) > 0,
                    "mfa_device_count": len(mfa_devices),
                }
            )
        total = len(users_mfa)
        mfa_enabled = sum(1 for u in users_mfa if u["mfa_enabled"])
        return self._make_evidence(
            evidence_type="mfa_status",
            data={
                "total_users": total,
                "mfa_enabled_count": mfa_enabled,
                "mfa_disabled_count": total - mfa_enabled,
                "mfa_coverage_pct": round(mfa_enabled / total * 100, 1) if total else 0,
                "users": users_mfa,
            },
            controls=["CC6.1", "CC6.3"],
        )

    def _collect_password_policy(self, raw: dict[str, Any]) -> Evidence:
        policy = raw.get("password_policy", {})
        return self._make_evidence(
            evidence_type="password_policy",
            data={
                "policy_exists": bool(policy),
                "minimum_length": policy.get("MinimumPasswordLength"),
                "require_symbols": policy.get("RequireSymbols"),
                "require_numbers": policy.get("RequireNumbers"),
                "require_uppercase": policy.get("RequireUppercaseCharacters"),
                "require_lowercase": policy.get("RequireLowercaseCharacters"),
                "max_age_days": policy.get("MaxPasswordAge"),
                "password_reuse_prevention": policy.get("PasswordReusePrevention"),
            },
            controls=["CC6.1"],
        )

    def _collect_access_key_rotation(self, raw: dict[str, Any]) -> Evidence:
        now = datetime.now(timezone.utc)
        stale_threshold = timedelta(days=90)
        key_details = []
        for u in raw["users"]:
            for key in u.get("AccessKeys", []):
                created = key.get("CreateDate")
                if isinstance(created, datetime):
                    age = now - created
                else:
                    age = timedelta(days=0)
                key_details.append(
                    {
                        "username": u["UserName"],
                        "access_key_id": key["AccessKeyId"],
                        "status": key["Status"],
                        "created": _isoformat(created),
                        "age_days": age.days,
                        "needs_rotation": age > stale_threshold,
                    }
                )
        stale_count = sum(1 for k in key_details if k["needs_rotation"])
        return self._make_evidence(
            evidence_type="access_key_rotation",
            data={
                "total_keys": len(key_details),
                "stale_keys": stale_count,
                "rotation_threshold_days": 90,
                "keys": key_details,
            },
            controls=["CC6.1", "CC6.3"],
        )

    def _collect_role_inventory(self, raw: dict[str, Any]) -> Evidence:
        roles = [
            {
                "role_name": r["RoleName"],
                "arn": r["Arn"],
                "created": _isoformat(r.get("CreateDate")),
            }
            for r in raw["roles"]
        ]
        return self._make_evidence(
            evidence_type="role_inventory",
            data={"role_count": len(roles), "roles": roles},
            controls=["CC6.1", "CC6.3"],
        )

    def _collect_policy_inventory(self, raw: dict[str, Any]) -> Evidence:
        policies = [
            {
                "policy_name": p["PolicyName"],
                "arn": p["Arn"],
                "attachment_count": p.get("AttachmentCount", 0),
                "updated": _isoformat(p.get("UpdateDate")),
            }
            for p in raw["policies"]
        ]
        return self._make_evidence(
            evidence_type="policy_inventory",
            data={"policy_count": len(policies), "policies": policies},
            controls=["CC6.1"],
        )


def _isoformat(dt: Any) -> str | None:
    if isinstance(dt, datetime):
        return dt.isoformat()
    return dt
