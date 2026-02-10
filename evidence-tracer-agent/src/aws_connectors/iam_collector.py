"""IAM Evidence Collector - Collects IAM evidence from AWS (or demo data)."""

import os
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3


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


def _collect_live(session: boto3.Session) -> dict[str, Any]:
    """Collect real IAM evidence from an AWS account via a boto3 session."""
    now = datetime.now(timezone.utc)
    iam = session.client("iam")

    evidence: dict[str, Any] = {}

    # --- Users ---
    users_resp = iam.list_users()
    user_items = []
    for u in users_resp.get("Users", []):
        mfa_resp = iam.list_mfa_devices(UserName=u["UserName"])
        keys_resp = iam.list_access_keys(UserName=u["UserName"])
        user_items.append(
            {
                "username": u["UserName"],
                "created": u["CreateDate"].isoformat(),
                "last_login": (
                    u["PasswordLastUsed"].isoformat()
                    if u.get("PasswordLastUsed")
                    else None
                ),
                "mfa_enabled": len(mfa_resp.get("MFADevices", [])) > 0,
                "access_keys": len(keys_resp.get("AccessKeyMetadata", [])),
            }
        )
    evidence["iam_users"] = {"collected_at": now.isoformat(), "items": user_items}

    # --- MFA status ---
    mfa_items = []
    for u in user_items:
        mfa_resp = iam.list_mfa_devices(UserName=u["username"])
        devices = mfa_resp.get("MFADevices", [])
        mfa_items.append(
            {
                "username": u["username"],
                "mfa_enabled": len(devices) > 0,
                "mfa_type": "virtual" if devices else None,
            }
        )
    evidence["mfa_status"] = {"collected_at": now.isoformat(), "items": mfa_items}

    # --- Access keys ---
    key_items = []
    for u in user_items:
        keys_resp = iam.list_access_keys(UserName=u["username"])
        for km in keys_resp.get("AccessKeyMetadata", []):
            last_used_resp = iam.get_access_key_last_used(
                AccessKeyId=km["AccessKeyId"]
            )
            last_used = last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
            key_items.append(
                {
                    "username": u["username"],
                    "key_id": km["AccessKeyId"][:8] + "...",
                    "status": km["Status"],
                    "created": km["CreateDate"].isoformat(),
                    "last_used": last_used.isoformat() if last_used else None,
                }
            )
    evidence["access_keys"] = {"collected_at": now.isoformat(), "items": key_items}

    # --- Password policy ---
    try:
        pp = iam.get_account_password_policy()["PasswordPolicy"]
        evidence["password_policy"] = {
            "collected_at": now.isoformat(),
            "items": [
                {
                    "minimum_length": pp.get("MinimumPasswordLength", 0),
                    "require_uppercase": pp.get("RequireUppercaseCharacters", False),
                    "require_lowercase": pp.get("RequireLowercaseCharacters", False),
                    "require_numbers": pp.get("RequireNumbers", False),
                    "require_symbols": pp.get("RequireSymbols", False),
                    "max_age_days": pp.get("MaxPasswordAge", 0),
                    "password_reuse_prevention": pp.get("PasswordReusePrevention", 0),
                }
            ],
        }
    except iam.exceptions.NoSuchEntityException:
        evidence["password_policy"] = {
            "collected_at": now.isoformat(),
            "items": [{"error": "No account password policy configured"}],
        }

    # --- Roles ---
    roles_resp = iam.list_roles()
    role_items = []
    for r in roles_resp.get("Roles", []):
        # Skip AWS service-linked roles
        if r.get("Path", "").startswith("/aws-service-role/"):
            continue
        trust = r.get("AssumeRolePolicyDocument", {})
        principals = []
        for stmt in trust.get("Statement", []):
            p = stmt.get("Principal", {})
            if isinstance(p, dict):
                principals.extend(p.get("Service", []))
            elif isinstance(p, str):
                principals.append(p)
        role_items.append(
            {
                "role_name": r["RoleName"],
                "created": r["CreateDate"].isoformat(),
                "last_used": (
                    r["RoleLastUsed"]["LastUsedDate"].isoformat()
                    if r.get("RoleLastUsed", {}).get("LastUsedDate")
                    else None
                ),
                "trust_policy": ", ".join(principals) if principals else "unknown",
            }
        )
    evidence["iam_roles"] = {"collected_at": now.isoformat(), "items": role_items}

    # --- Customer-managed policies ---
    policies_resp = iam.list_policies(Scope="Local")
    policy_items = []
    overly_permissive = []
    for pol in policies_resp.get("Policies", []):
        ver = iam.get_policy_version(
            PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"]
        )
        doc = ver["PolicyVersion"]["Document"]
        actions_set: list[str] = []
        resources_set: list[str] = []
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            act = stmt.get("Action", [])
            res = stmt.get("Resource", [])
            if isinstance(act, str):
                act = [act]
            if isinstance(res, str):
                res = [res]
            actions_set.extend(act)
            resources_set.extend(res)

        # Determine attached entities
        entities_resp = iam.list_entities_for_policy(PolicyArn=pol["Arn"])
        attached_to = (
            [g["GroupName"] for g in entities_resp.get("PolicyGroups", [])]
            + [u["UserName"] for u in entities_resp.get("PolicyUsers", [])]
            + [r["RoleName"] for r in entities_resp.get("PolicyRoles", [])]
        )

        policy_items.append(
            {
                "policy_name": pol["PolicyName"],
                "attached_to": attached_to,
                "is_aws_managed": False,
                "actions": actions_set,
                "resources": resources_set,
            }
        )

        if "*" in actions_set and "*" in resources_set:
            overly_permissive.append(
                {
                    "policy_name": pol["PolicyName"],
                    "attached_to": attached_to,
                    "risk": "high",
                    "reason": "Uses wildcard (*) for both actions and resources",
                }
            )

    evidence["iam_policies"] = {"collected_at": now.isoformat(), "items": policy_items}
    evidence["overly_permissive_policies"] = {
        "collected_at": now.isoformat(),
        "items": overly_permissive,
    }

    return evidence


def collect(session: boto3.Session | None = None) -> dict[str, Any]:
    """Collect IAM evidence. Uses demo data when DEMO_MODE is set.

    Args:
        session: Optional boto3 Session with assumed-role credentials.
                 Required for live collection. Ignored in demo mode.

    Returns:
        Dictionary of evidence keyed by evidence type.
    """
    demo_mode = os.environ.get("DEMO_MODE", "true").lower() in ("true", "1", "yes")

    if demo_mode:
        print("[IAM Collector] Running in DEMO_MODE - using synthetic evidence")
        return _generate_demo_evidence()

    if session is None:
        raise RuntimeError(
            "Live AWS collection requires a boto3 Session. "
            "Either set DEMO_MODE=true or provide a session via STS role assumption."
        )

    print("[IAM Collector] Collecting live IAM evidence...")
    return _collect_live(session)
