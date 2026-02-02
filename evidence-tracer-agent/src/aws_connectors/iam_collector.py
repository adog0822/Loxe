"""IAM Evidence Collector - Collects IAM evidence from AWS (or demo data)."""

import os
from datetime import datetime, timedelta, timezone
from typing import Any


def _generate_demo_evidence() -> dict[str, Any]:
    """Generate realistic demo IAM evidence without AWS credentials."""
    now = datetime.now(timezone.utc)

    return {
        "iam_users": {
            "collected_at": now.isoformat(),
            "items": [
                {
                    "username": "admin-user",
                    "created": (now - timedelta(days=365)).isoformat(),
                    "last_login": (now - timedelta(days=2)).isoformat(),
                    "mfa_enabled": True,
                    "access_keys": 1,
                },
                {
                    "username": "developer-1",
                    "created": (now - timedelta(days=180)).isoformat(),
                    "last_login": (now - timedelta(hours=6)).isoformat(),
                    "mfa_enabled": True,
                    "access_keys": 1,
                },
                {
                    "username": "service-account",
                    "created": (now - timedelta(days=90)).isoformat(),
                    "last_login": None,
                    "mfa_enabled": False,
                    "access_keys": 2,
                },
                {
                    "username": "stale-user",
                    "created": (now - timedelta(days=400)).isoformat(),
                    "last_login": (now - timedelta(days=95)).isoformat(),
                    "mfa_enabled": False,
                    "access_keys": 1,
                },
            ],
        },
        "iam_policies": {
            "collected_at": now.isoformat(),
            "items": [
                {
                    "policy_name": "AdminFullAccess",
                    "attached_to": ["admin-user"],
                    "is_aws_managed": False,
                    "actions": ["*"],
                    "resources": ["*"],
                },
                {
                    "policy_name": "DeveloperAccess",
                    "attached_to": ["developer-1"],
                    "is_aws_managed": False,
                    "actions": ["s3:*", "ec2:Describe*", "logs:*"],
                    "resources": ["arn:aws:s3:::dev-*", "*", "*"],
                },
                {
                    "policy_name": "ServiceAccountPolicy",
                    "attached_to": ["service-account"],
                    "is_aws_managed": False,
                    "actions": ["sqs:SendMessage", "sqs:ReceiveMessage"],
                    "resources": ["arn:aws:sqs:us-east-1:123456789:app-queue"],
                },
            ],
        },
        "mfa_status": {
            "collected_at": now.isoformat(),
            "items": [
                {"username": "admin-user", "mfa_enabled": True, "mfa_type": "virtual"},
                {"username": "developer-1", "mfa_enabled": True, "mfa_type": "virtual"},
                {"username": "service-account", "mfa_enabled": False, "mfa_type": None},
                {"username": "stale-user", "mfa_enabled": False, "mfa_type": None},
            ],
        },
        "access_keys": {
            "collected_at": now.isoformat(),
            "items": [
                {
                    "username": "admin-user",
                    "key_id": "AKIA...DEMO1",
                    "status": "Active",
                    "created": (now - timedelta(days=30)).isoformat(),
                    "last_used": (now - timedelta(days=1)).isoformat(),
                },
                {
                    "username": "developer-1",
                    "key_id": "AKIA...DEMO2",
                    "status": "Active",
                    "created": (now - timedelta(days=60)).isoformat(),
                    "last_used": (now - timedelta(hours=6)).isoformat(),
                },
                {
                    "username": "service-account",
                    "key_id": "AKIA...DEMO3",
                    "status": "Active",
                    "created": (now - timedelta(days=200)).isoformat(),
                    "last_used": (now - timedelta(days=1)).isoformat(),
                },
                {
                    "username": "service-account",
                    "key_id": "AKIA...DEMO4",
                    "status": "Active",
                    "created": (now - timedelta(days=200)).isoformat(),
                    "last_used": (now - timedelta(days=150)).isoformat(),
                },
                {
                    "username": "stale-user",
                    "key_id": "AKIA...DEMO5",
                    "status": "Active",
                    "created": (now - timedelta(days=400)).isoformat(),
                    "last_used": (now - timedelta(days=95)).isoformat(),
                },
            ],
        },
        "password_policy": {
            "collected_at": now.isoformat(),
            "items": [
                {
                    "minimum_length": 14,
                    "require_uppercase": True,
                    "require_lowercase": True,
                    "require_numbers": True,
                    "require_symbols": True,
                    "max_age_days": 90,
                    "password_reuse_prevention": 12,
                }
            ],
        },
        "iam_roles": {
            "collected_at": now.isoformat(),
            "items": [
                {
                    "role_name": "EC2-WebServer-Role",
                    "created": (now - timedelta(days=120)).isoformat(),
                    "last_used": (now - timedelta(hours=1)).isoformat(),
                    "trust_policy": "ec2.amazonaws.com",
                },
                {
                    "role_name": "Lambda-Processor-Role",
                    "created": (now - timedelta(days=60)).isoformat(),
                    "last_used": (now - timedelta(minutes=15)).isoformat(),
                    "trust_policy": "lambda.amazonaws.com",
                },
            ],
        },
        "overly_permissive_policies": {
            "collected_at": now.isoformat(),
            "items": [
                {
                    "policy_name": "AdminFullAccess",
                    "attached_to": ["admin-user"],
                    "risk": "high",
                    "reason": "Uses wildcard (*) for both actions and resources",
                },
            ],
        },
    }


def collect() -> dict[str, Any]:
    """Collect IAM evidence. Uses demo data when DEMO_MODE is set.

    Returns:
        Dictionary of evidence keyed by evidence type.
    """
    demo_mode = os.environ.get("DEMO_MODE", "true").lower() in ("true", "1", "yes")

    if demo_mode:
        print("[IAM Collector] Running in DEMO_MODE - using synthetic evidence")
        return _generate_demo_evidence()

    # Real AWS collection would go here (requires boto3 + credentials)
    raise RuntimeError(
        "Live AWS collection is not yet implemented. "
        "Set DEMO_MODE=true to use synthetic evidence."
    )
