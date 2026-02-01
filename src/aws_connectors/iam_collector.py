"""
IAM Collector - Collects AWS IAM user evidence for SOC 2 compliance controls.

Supports DEMO_MODE for generating realistic fake data without AWS credentials.

Controls mapped:
    CC6.1 - Logical and Physical Access Controls
    CC6.3 - Role-Based Access and Least Privilege
    CC6.7 - Restriction and Management of Access Credentials
"""

import json
import logging
import os
import random
import uuid
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"

MAPPED_CONTROLS = ["CC6.1", "CC6.3", "CC6.7"]

# ---------------------------------------------------------------------------
# Demo-mode configuration
# ---------------------------------------------------------------------------

DEMO_USERNAMES = [
    "admin",
    "developer",
    "ci-cd-bot",
    "analytics-user",
    "backup-admin",
    "read-only-auditor",
    "s3-manager",
    "lambda-executor",
    "cloudwatch-admin",
    "security-auditor",
]

DEMO_USER_PROFILES = {
    "admin": {
        "mfa_enabled": True,
        "policies": ["AdministratorAccess"],
        "groups": ["Admins"],
        "has_old_access_key": False,
    },
    "developer": {
        "mfa_enabled": True,
        "policies": ["PowerUserAccess"],
        "groups": ["Developers"],
        "has_old_access_key": False,
    },
    "ci-cd-bot": {
        "mfa_enabled": False,
        "policies": ["AmazonEC2FullAccess", "AmazonS3FullAccess", "AWSCodePipeline_FullAccess"],
        "groups": ["CICD"],
        "has_old_access_key": True,
    },
    "analytics-user": {
        "mfa_enabled": True,
        "policies": ["ReadOnlyAccess", "AmazonAthenaFullAccess"],
        "groups": ["Analytics"],
        "has_old_access_key": False,
    },
    "backup-admin": {
        "mfa_enabled": True,
        "policies": ["AWSBackupFullAccess", "AmazonS3FullAccess"],
        "groups": ["BackupOps"],
        "has_old_access_key": True,
    },
    "read-only-auditor": {
        "mfa_enabled": True,
        "policies": ["ReadOnlyAccess", "SecurityAudit"],
        "groups": ["Auditors"],
        "has_old_access_key": False,
    },
    "s3-manager": {
        "mfa_enabled": True,
        "policies": ["AmazonS3FullAccess"],
        "groups": ["StorageTeam"],
        "has_old_access_key": False,
    },
    "lambda-executor": {
        "mfa_enabled": False,
        "policies": ["AWSLambda_FullAccess", "AmazonDynamoDBFullAccess"],
        "groups": ["Serverless"],
        "has_old_access_key": True,
    },
    "cloudwatch-admin": {
        "mfa_enabled": True,
        "policies": ["CloudWatchFullAccess", "AmazonSNSFullAccess"],
        "groups": ["Monitoring"],
        "has_old_access_key": False,
    },
    "security-auditor": {
        "mfa_enabled": False,
        "policies": ["SecurityAudit", "IAMReadOnlyAccess"],
        "groups": ["SecurityTeam"],
        "has_old_access_key": False,
    },
}


# ---------------------------------------------------------------------------
# Demo data generators
# ---------------------------------------------------------------------------

def _random_date_between(start_days_ago: int, end_days_ago: int) -> datetime:
    """Return a random UTC datetime between *start_days_ago* and *end_days_ago*."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=start_days_ago)
    end = now - timedelta(days=end_days_ago)
    delta = (end - start).total_seconds()
    random_seconds = random.random() * delta
    return start + timedelta(seconds=random_seconds)


def _generate_demo_access_key(user: str, is_old: bool) -> dict:
    """Generate a fake access key metadata dict."""
    if is_old:
        created = _random_date_between(730, 365)
    else:
        created = _random_date_between(90, 1)

    last_used = _random_date_between(
        max((datetime.now(timezone.utc) - created).days, 1), 0
    )

    return {
        "AccessKeyId": f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
        "Status": "Active",
        "CreateDate": created.isoformat(),
        "LastUsedDate": last_used.isoformat(),
        "LastUsedService": random.choice(["s3", "ec2", "iam", "lambda", "sts"]),
        "LastUsedRegion": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
        "AgeDays": (datetime.now(timezone.utc) - created).days,
    }


def _generate_demo_user(username: str) -> dict:
    """Build a complete demo IAM user record."""
    profile = DEMO_USER_PROFILES[username]
    creation_date = _random_date_between(365, 30)
    user_id = f"AIDA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}"
    arn = f"arn:aws:iam::123456789012:user/{username}"

    access_keys = []
    if profile["has_old_access_key"]:
        access_keys.append(_generate_demo_access_key(username, is_old=True))
    access_keys.append(_generate_demo_access_key(username, is_old=False))

    password_last_used = _random_date_between(30, 0) if profile["mfa_enabled"] else None

    return {
        "UserName": username,
        "UserId": user_id,
        "Arn": arn,
        "CreateDate": creation_date.isoformat(),
        "PasswordLastUsed": password_last_used.isoformat() if password_last_used else None,
        "MFAEnabled": profile["mfa_enabled"],
        "MFADevices": (
            [{"SerialNumber": f"arn:aws:iam::123456789012:mfa/{username}", "EnableDate": creation_date.isoformat()}]
            if profile["mfa_enabled"]
            else []
        ),
        "AccessKeys": access_keys,
        "AttachedPolicies": [
            {"PolicyName": p, "PolicyArn": f"arn:aws:iam::aws:policy/{p}"}
            for p in profile["policies"]
        ],
        "Groups": profile["groups"],
        "Tags": [
            {"Key": "Environment", "Value": random.choice(["production", "staging", "development"])},
            {"Key": "ManagedBy", "Value": "evidence-tracer"},
        ],
    }


def _generate_demo_data() -> dict:
    """Return a full demo evidence payload for IAM users."""
    users = [_generate_demo_user(u) for u in DEMO_USERNAMES]

    mfa_enabled_count = sum(1 for u in users if u["MFAEnabled"])
    old_key_users = [
        u["UserName"]
        for u in users
        if any(k["AgeDays"] >= 365 for k in u["AccessKeys"])
    ]

    return {
        "metadata": {
            "collector": "iam_collector",
            "demo_mode": True,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "account_id": "123456789012",
            "region": "global",
            "controls": MAPPED_CONTROLS,
        },
        "summary": {
            "total_users": len(users),
            "mfa_enabled_count": mfa_enabled_count,
            "mfa_disabled_count": len(users) - mfa_enabled_count,
            "mfa_compliance_pct": round((mfa_enabled_count / len(users)) * 100, 1),
            "users_with_old_access_keys": old_key_users,
            "old_access_key_count": len(old_key_users),
        },
        "users": users,
        "findings": _build_findings(users),
    }


# ---------------------------------------------------------------------------
# Findings builder (shared between demo and live modes)
# ---------------------------------------------------------------------------

def _build_findings(users: list[dict]) -> list[dict]:
    """Generate compliance findings from a list of IAM user records."""
    findings = []

    for user in users:
        if not user["MFAEnabled"]:
            findings.append({
                "id": str(uuid.uuid4()),
                "severity": "HIGH",
                "control": "CC6.1",
                "title": f"MFA not enabled for user '{user['UserName']}'",
                "description": (
                    f"IAM user '{user['UserName']}' does not have multi-factor "
                    "authentication enabled. MFA adds a critical layer of protection "
                    "for console and API access."
                ),
                "resource_arn": user["Arn"],
                "recommendation": "Enable MFA for this IAM user immediately.",
            })

        for key in user["AccessKeys"]:
            if key["AgeDays"] >= 365:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "severity": "MEDIUM",
                    "control": "CC6.7",
                    "title": f"Access key older than 365 days for user '{user['UserName']}'",
                    "description": (
                        f"Access key {key['AccessKeyId']} for user "
                        f"'{user['UserName']}' is {key['AgeDays']} days old. "
                        "Keys should be rotated regularly."
                    ),
                    "resource_arn": user["Arn"],
                    "recommendation": "Rotate this access key and deactivate the old one.",
                })

        admin_policies = {"AdministratorAccess", "PowerUserAccess"}
        attached = {p["PolicyName"] for p in user["AttachedPolicies"]}
        if attached & admin_policies:
            findings.append({
                "id": str(uuid.uuid4()),
                "severity": "LOW",
                "control": "CC6.3",
                "title": f"Broad permissions detected for user '{user['UserName']}'",
                "description": (
                    f"IAM user '{user['UserName']}' has broad policies attached: "
                    f"{', '.join(attached & admin_policies)}. Consider applying "
                    "least-privilege principles."
                ),
                "resource_arn": user["Arn"],
                "recommendation": "Review and scope down permissions to least privilege.",
            })

    return findings


# ---------------------------------------------------------------------------
# Live AWS collection (boto3)
# ---------------------------------------------------------------------------

def _collect_live_data() -> dict:
    """Collect real IAM evidence from AWS using boto3."""
    try:
        import boto3
    except ImportError:
        logger.error("boto3 is required for live mode. Install with: pip install boto3")
        raise

    iam = boto3.client("iam")
    sts = boto3.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    logger.info("Collecting IAM evidence for account %s", account_id)

    paginator = iam.get_paginator("list_users")
    users = []

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]

            # MFA devices
            mfa_response = iam.list_mfa_devices(UserName=username)
            mfa_devices = mfa_response.get("MFADevices", [])
            mfa_enabled = len(mfa_devices) > 0

            # Access keys
            key_response = iam.list_access_keys(UserName=username)
            access_keys = []
            for key_meta in key_response.get("AccessKeyMetadata", []):
                key_id = key_meta["AccessKeyId"]
                create_date = key_meta["CreateDate"]
                age_days = (datetime.now(timezone.utc) - create_date.replace(tzinfo=timezone.utc)).days

                last_used_resp = iam.get_access_key_last_used(AccessKeyId=key_id)
                last_used_info = last_used_resp.get("AccessKeyLastUsed", {})

                access_keys.append({
                    "AccessKeyId": key_id,
                    "Status": key_meta["Status"],
                    "CreateDate": create_date.isoformat(),
                    "LastUsedDate": (
                        last_used_info["LastUsedDate"].isoformat()
                        if "LastUsedDate" in last_used_info
                        else None
                    ),
                    "LastUsedService": last_used_info.get("ServiceName"),
                    "LastUsedRegion": last_used_info.get("Region"),
                    "AgeDays": age_days,
                })

            # Attached policies
            policy_response = iam.list_attached_user_policies(UserName=username)
            attached_policies = [
                {"PolicyName": p["PolicyName"], "PolicyArn": p["PolicyArn"]}
                for p in policy_response.get("AttachedPolicies", [])
            ]

            # Groups
            groups_response = iam.list_groups_for_user(UserName=username)
            groups = [g["GroupName"] for g in groups_response.get("Groups", [])]

            # Tags
            tags_response = iam.list_user_tags(UserName=username)
            tags = tags_response.get("Tags", [])

            # Serialize MFA devices
            serialized_mfa = [
                {
                    "SerialNumber": d["SerialNumber"],
                    "EnableDate": d["EnableDate"].isoformat() if hasattr(d["EnableDate"], "isoformat") else d["EnableDate"],
                }
                for d in mfa_devices
            ]

            users.append({
                "UserName": username,
                "UserId": user["UserId"],
                "Arn": user["Arn"],
                "CreateDate": user["CreateDate"].isoformat(),
                "PasswordLastUsed": (
                    user["PasswordLastUsed"].isoformat()
                    if user.get("PasswordLastUsed")
                    else None
                ),
                "MFAEnabled": mfa_enabled,
                "MFADevices": serialized_mfa,
                "AccessKeys": access_keys,
                "AttachedPolicies": attached_policies,
                "Groups": groups,
                "Tags": tags,
            })

    mfa_enabled_count = sum(1 for u in users if u["MFAEnabled"])
    old_key_users = [
        u["UserName"]
        for u in users
        if any(k["AgeDays"] >= 365 for k in u["AccessKeys"])
    ]

    return {
        "metadata": {
            "collector": "iam_collector",
            "demo_mode": False,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "account_id": account_id,
            "region": "global",
            "controls": MAPPED_CONTROLS,
        },
        "summary": {
            "total_users": len(users),
            "mfa_enabled_count": mfa_enabled_count,
            "mfa_disabled_count": len(users) - mfa_enabled_count,
            "mfa_compliance_pct": round((mfa_enabled_count / len(users)) * 100, 1) if users else 0.0,
            "users_with_old_access_keys": old_key_users,
            "old_access_key_count": len(old_key_users),
        },
        "users": users,
        "findings": _build_findings(users),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect() -> dict:
    """Collect IAM user evidence.

    Returns demo data when DEMO_MODE=true, otherwise queries AWS via boto3.
    """
    if DEMO_MODE:
        logger.info("DEMO_MODE enabled – generating synthetic IAM evidence")
        return _generate_demo_data()

    logger.info("Collecting live IAM evidence from AWS")
    return _collect_live_data()


def get_mapped_controls() -> list[str]:
    """Return the SOC 2 controls this collector maps to."""
    return list(MAPPED_CONTROLS)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    result = collect()
    print(json.dumps(result, indent=2, default=str))
