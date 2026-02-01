"""
IAM Collector - Collects AWS IAM evidence for SOC 2 compliance.

When DEMO_MODE=true, generates 10 realistic fake IAM users with
MFA status, access key ages, policies, last-activity timestamps,
and group memberships.
"""

import os
import json
import random
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class AccessKey:
    access_key_id: str
    status: str                # Active / Inactive
    create_date: str
    last_used_date: Optional[str]
    last_used_service: Optional[str]
    age_days: int = 0


@dataclass
class IAMUser:
    user_name: str
    user_id: str
    arn: str
    create_date: str
    password_last_used: Optional[str]
    mfa_enabled: bool
    mfa_devices: int
    access_keys: list[AccessKey] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    attached_policies: list[str] = field(default_factory=list)
    inline_policies: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    password_last_changed: Optional[str] = None
    password_next_rotation: Optional[str] = None


# ── Demo data generation ────────────────────────────────────────────────

DEMO_USERS = [
    {
        "name": "alice.chen",
        "department": "Engineering",
        "role": "Lead Engineer",
        "groups": ["Developers", "SRETeam", "CodeReviewers"],
        "policies": ["arn:aws:iam::policy/PowerUserAccess", "arn:aws:iam::policy/CloudWatchFullAccess"],
        "mfa": True,
        "key_age_days": 45,
        "active": True,
    },
    {
        "name": "bob.martinez",
        "department": "DevOps",
        "role": "DevOps Engineer",
        "groups": ["Developers", "InfraTeam"],
        "policies": ["arn:aws:iam::policy/AdministratorAccess"],
        "mfa": True,
        "key_age_days": 12,
        "active": True,
    },
    {
        "name": "carol.johnson",
        "department": "Security",
        "role": "Security Analyst",
        "groups": ["SecurityTeam", "ComplianceAuditors"],
        "policies": ["arn:aws:iam::policy/SecurityAudit", "arn:aws:iam::policy/IAMReadOnlyAccess"],
        "mfa": True,
        "key_age_days": 30,
        "active": True,
    },
    {
        "name": "david.kim",
        "department": "Engineering",
        "role": "Backend Developer",
        "groups": ["Developers"],
        "policies": ["arn:aws:iam::policy/PowerUserAccess"],
        "mfa": True,
        "key_age_days": 88,
        "active": True,
    },
    {
        "name": "elena.rodriguez",
        "department": "Finance",
        "role": "Finance Manager",
        "groups": ["FinanceTeam", "BillingAdmins"],
        "policies": ["arn:aws:iam::policy/job-function/Billing", "arn:aws:iam::policy/AWSBudgetsActionsWithAWSResourceControlAccess"],
        "mfa": True,
        "key_age_days": 60,
        "active": True,
    },
    {
        "name": "frank.wilson",
        "department": "Engineering",
        "role": "Junior Developer",
        "groups": ["Developers"],
        "policies": ["arn:aws:iam::policy/PowerUserAccess"],
        "mfa": False,  # MFA not enabled - compliance gap
        "key_age_days": 200,  # Stale key - compliance gap
        "active": True,
    },
    {
        "name": "grace.lee",
        "department": "HR",
        "role": "HR Director",
        "groups": ["HRTeam"],
        "policies": ["arn:aws:iam::policy/ReadOnlyAccess"],
        "mfa": True,
        "key_age_days": 15,
        "active": True,
    },
    {
        "name": "henry.patel",
        "department": "Engineering",
        "role": "Data Engineer",
        "groups": ["Developers", "DataTeam"],
        "policies": ["arn:aws:iam::policy/AmazonS3FullAccess", "arn:aws:iam::policy/AmazonRedshiftFullAccess"],
        "mfa": True,
        "key_age_days": 55,
        "active": True,
    },
    {
        "name": "irene.thompson",
        "department": "Operations",
        "role": "Former Contractor",
        "groups": ["Contractors"],
        "policies": ["arn:aws:iam::policy/PowerUserAccess"],
        "mfa": False,  # MFA not enabled - compliance gap
        "key_age_days": 320,  # Very stale - compliance gap (terminated user?)
        "active": False,  # Inactive but account still exists
    },
    {
        "name": "james.nguyen",
        "department": "Engineering",
        "role": "CTO",
        "groups": ["Developers", "SRETeam", "SecurityTeam", "LeadershipTeam"],
        "policies": ["arn:aws:iam::policy/AdministratorAccess"],
        "mfa": True,
        "key_age_days": 25,
        "active": True,
    },
]


def _generate_user_id(name: str) -> str:
    """Generate a deterministic fake AWS user ID."""
    h = hashlib.sha256(name.encode()).hexdigest()[:20].upper()
    return f"AIDA{h[:16]}"


def _generate_access_key_id(name: str) -> str:
    """Generate a deterministic fake access key ID."""
    h = hashlib.sha256(f"key-{name}".encode()).hexdigest()[:16].upper()
    return f"AKIA{h}"


def _build_demo_user(spec: dict) -> IAMUser:
    """Build a realistic IAMUser from a demo spec."""
    now = datetime.utcnow()
    name = spec["name"]

    create_offset = random.randint(180, 900)
    create_date = (now - timedelta(days=create_offset)).isoformat() + "Z"

    key_create = now - timedelta(days=spec["key_age_days"])
    last_used = now - timedelta(days=random.randint(0, 3)) if spec["active"] else now - timedelta(days=spec["key_age_days"])

    services = ["s3", "ec2", "sts", "lambda", "cloudwatch", "iam", "dynamodb", "rds", "redshift"]
    last_service = random.choice(services)

    access_key = AccessKey(
        access_key_id=_generate_access_key_id(name),
        status="Active" if spec["active"] else "Inactive",
        create_date=key_create.isoformat() + "Z",
        last_used_date=last_used.isoformat() + "Z",
        last_used_service=last_service,
        age_days=spec["key_age_days"],
    )

    pwd_last_used = (now - timedelta(days=random.randint(0, 7))).isoformat() + "Z" if spec["active"] else None
    pwd_last_changed = (now - timedelta(days=random.randint(30, 90))).isoformat() + "Z"
    pwd_next_rotation = (now + timedelta(days=random.randint(0, 60))).isoformat() + "Z"

    return IAMUser(
        user_name=name,
        user_id=_generate_user_id(name),
        arn=f"arn:aws:iam::123456789012:user/{name}",
        create_date=create_date,
        password_last_used=pwd_last_used,
        mfa_enabled=spec["mfa"],
        mfa_devices=1 if spec["mfa"] else 0,
        access_keys=[access_key],
        groups=spec["groups"],
        attached_policies=spec["policies"],
        inline_policies=[],
        tags={"Department": spec["department"], "Role": spec["role"]},
        password_last_changed=pwd_last_changed,
        password_next_rotation=pwd_next_rotation,
    )


class IAMCollector:
    """
    Collects IAM user data from AWS or generates demo data.

    When DEMO_MODE env var is set to 'true', generates 10 realistic
    fake IAM users with various compliance states (MFA gaps, stale
    keys, inactive accounts).
    """

    def __init__(self):
        self.demo_mode = os.getenv("DEMO_MODE", "false").lower() == "true"
        self.account_id = os.getenv("AWS_ACCOUNT_ID", "123456789012")
        self.collected_at = datetime.utcnow().isoformat() + "Z"

    def collect(self) -> list[IAMUser]:
        """Collect IAM users. Uses demo data if DEMO_MODE=true."""
        if self.demo_mode:
            return self._collect_demo()
        return self._collect_live()

    def _collect_demo(self) -> list[IAMUser]:
        """Generate 10 realistic fake IAM users."""
        random.seed(42)  # Deterministic for reproducibility
        users = [_build_demo_user(spec) for spec in DEMO_USERS]
        return users

    def _collect_live(self) -> list[IAMUser]:
        """
        Collect from real AWS IAM API.
        Requires boto3 and valid AWS credentials.
        """
        raise NotImplementedError(
            "Live AWS collection not implemented in MVP. "
            "Set DEMO_MODE=true to use demo data."
        )

    def collect_and_export(self, output_path: str) -> list[IAMUser]:
        """Collect users and export to JSON."""
        users = self.collect()
        data = {
            "collected_at": self.collected_at,
            "account_id": self.account_id,
            "demo_mode": self.demo_mode,
            "user_count": len(users),
            "users": [asdict(u) for u in users],
        }
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return users

    def get_summary(self, users: list[IAMUser]) -> dict:
        """Generate a quick summary of IAM posture."""
        total = len(users)
        mfa_enabled = sum(1 for u in users if u.mfa_enabled)
        stale_keys = sum(
            1 for u in users
            for k in u.access_keys
            if k.age_days > 90
        )
        inactive_users = sum(
            1 for u in users
            if not any(k.status == "Active" for k in u.access_keys)
        )
        admin_users = sum(
            1 for u in users
            if any("AdministratorAccess" in p for p in u.attached_policies)
        )

        return {
            "total_users": total,
            "mfa_enabled": mfa_enabled,
            "mfa_disabled": total - mfa_enabled,
            "mfa_coverage_pct": round(mfa_enabled / total * 100, 1) if total else 0,
            "stale_access_keys": stale_keys,
            "inactive_users": inactive_users,
            "admin_users": admin_users,
        }
