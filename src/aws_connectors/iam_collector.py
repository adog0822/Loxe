import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
import yaml

logger = logging.getLogger(__name__)


class IAMCollector:
    """Collects IAM user evidence from AWS accounts.

    Supports a demo mode (DEMO_MODE=true) that returns realistic
    simulated data without making any AWS API calls.
    """

    def __init__(self, session: boto3.Session | None = None):
        self.demo_mode = os.getenv("DEMO_MODE", "false").lower() == "true"

        if self.demo_mode:
            logger.info("IAMCollector running in DEMO MODE – no AWS calls will be made")
            self._demo_config = self._load_demo_config()
            self.client = None
        else:
            session = session or boto3.Session()
            self.client = session.client("iam")

    @staticmethod
    def _load_demo_config() -> dict[str, Any]:
        config_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "config", "demo_config.yaml"
        )
        config_path = os.path.normpath(config_path)
        try:
            with open(config_path, "r") as fh:
                return yaml.safe_load(fh)
        except FileNotFoundError:
            logger.warning("demo_config.yaml not found at %s – using built-in defaults", config_path)
            return {}

    # ------------------------------------------------------------------
    # Demo-data generation
    # ------------------------------------------------------------------

    def _generate_demo_evidence(self) -> list[dict[str, Any]]:
        """Return a list of 10 realistic fake IAM user records."""

        now = datetime.now(timezone.utc)

        users: list[dict[str, Any]] = [
            {
                "UserName": "admin",
                "UserId": "AIDADEMO000000000ADMN",
                "Arn": "arn:aws:iam::123456789012:user/admin",
                "CreateDate": (now - timedelta(days=820)).isoformat(),
                "MFAEnabled": True,
                "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/admin", "EnableDate": (now - timedelta(days=800)).isoformat()}],
                "AccessKeys": [
                    {"AccessKeyId": "AKIADEMO00000000ADM1", "Status": "Active", "CreateDate": (now - timedelta(days=120)).isoformat()},
                ],
                "AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}],
                "Groups": ["Admins"],
            },
            {
                "UserName": "developer",
                "UserId": "AIDADEMO000000000DEVL",
                "Arn": "arn:aws:iam::123456789012:user/developer",
                "CreateDate": (now - timedelta(days=600)).isoformat(),
                "MFAEnabled": True,
                "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/developer", "EnableDate": (now - timedelta(days=590)).isoformat()}],
                "AccessKeys": [
                    {"AccessKeyId": "AKIADEMO00000000DEV1", "Status": "Active", "CreateDate": (now - timedelta(days=180)).isoformat()},
                ],
                "AttachedPolicies": [{"PolicyName": "PowerUserAccess", "PolicyArn": "arn:aws:iam::aws:policy/PowerUserAccess"}],
                "Groups": ["Developers"],
            },
            {
                "UserName": "ci-cd-bot",
                "UserId": "AIDADEMO000000000CICD",
                "Arn": "arn:aws:iam::123456789012:user/ci-cd-bot",
                "CreateDate": (now - timedelta(days=500)).isoformat(),
                "MFAEnabled": False,
                "MFADevices": [],
                "AccessKeys": [
                    {"AccessKeyId": "AKIADEMO00000000CIC1", "Status": "Active", "CreateDate": (now - timedelta(days=400)).isoformat()},
                    {"AccessKeyId": "AKIADEMO00000000CIC2", "Status": "Inactive", "CreateDate": (now - timedelta(days=480)).isoformat()},
                ],
                "AttachedPolicies": [
                    {"PolicyName": "AmazonS3FullAccess", "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"},
                    {"PolicyName": "AmazonEC2FullAccess", "PolicyArn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"},
                ],
                "Groups": ["CICD"],
            },
            {
                "UserName": "read-only-auditor",
                "UserId": "AIDADEMO000000000RAUD",
                "Arn": "arn:aws:iam::123456789012:user/read-only-auditor",
                "CreateDate": (now - timedelta(days=300)).isoformat(),
                "MFAEnabled": True,
                "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/read-only-auditor", "EnableDate": (now - timedelta(days=295)).isoformat()}],
                "AccessKeys": [],
                "AttachedPolicies": [{"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}],
                "Groups": ["Auditors"],
            },
            {
                "UserName": "s3-manager",
                "UserId": "AIDADEMO000000000S3MG",
                "Arn": "arn:aws:iam::123456789012:user/s3-manager",
                "CreateDate": (now - timedelta(days=450)).isoformat(),
                "MFAEnabled": True,
                "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/s3-manager", "EnableDate": (now - timedelta(days=440)).isoformat()}],
                "AccessKeys": [
                    {"AccessKeyId": "AKIADEMO00000000S3M1", "Status": "Active", "CreateDate": (now - timedelta(days=90)).isoformat()},
                ],
                "AttachedPolicies": [{"PolicyName": "AmazonS3FullAccess", "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"}],
                "Groups": ["StorageTeam"],
            },
            {
                "UserName": "data-scientist",
                "UserId": "AIDADEMO000000000DSCI",
                "Arn": "arn:aws:iam::123456789012:user/data-scientist",
                "CreateDate": (now - timedelta(days=200)).isoformat(),
                "MFAEnabled": True,
                "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/data-scientist", "EnableDate": (now - timedelta(days=195)).isoformat()}],
                "AccessKeys": [
                    {"AccessKeyId": "AKIADEMO00000000DSC1", "Status": "Active", "CreateDate": (now - timedelta(days=60)).isoformat()},
                ],
                "AttachedPolicies": [
                    {"PolicyName": "AmazonSageMakerFullAccess", "PolicyArn": "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"},
                    {"PolicyName": "AmazonS3ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"},
                ],
                "Groups": ["DataTeam"],
            },
            {
                "UserName": "legacy-service-account",
                "UserId": "AIDADEMO000000000LGSA",
                "Arn": "arn:aws:iam::123456789012:user/legacy-service-account",
                "CreateDate": (now - timedelta(days=900)).isoformat(),
                "MFAEnabled": False,
                "MFADevices": [],
                "AccessKeys": [
                    {"AccessKeyId": "AKIADEMO00000000LGS1", "Status": "Active", "CreateDate": (now - timedelta(days=750)).isoformat()},
                ],
                "AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}],
                "Groups": [],
            },
            {
                "UserName": "intern-temp",
                "UserId": "AIDADEMO000000000ITMP",
                "Arn": "arn:aws:iam::123456789012:user/intern-temp",
                "CreateDate": (now - timedelta(days=45)).isoformat(),
                "MFAEnabled": False,
                "MFADevices": [],
                "AccessKeys": [
                    {"AccessKeyId": "AKIADEMO00000000INT1", "Status": "Active", "CreateDate": (now - timedelta(days=45)).isoformat()},
                ],
                "AttachedPolicies": [{"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}],
                "Groups": ["Interns"],
            },
            {
                "UserName": "devops-lead",
                "UserId": "AIDADEMO000000000DVOP",
                "Arn": "arn:aws:iam::123456789012:user/devops-lead",
                "CreateDate": (now - timedelta(days=700)).isoformat(),
                "MFAEnabled": True,
                "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/devops-lead", "EnableDate": (now - timedelta(days=690)).isoformat()}],
                "AccessKeys": [
                    {"AccessKeyId": "AKIADEMO00000000DVO1", "Status": "Active", "CreateDate": (now - timedelta(days=365)).isoformat()},
                ],
                "AttachedPolicies": [{"PolicyName": "PowerUserAccess", "PolicyArn": "arn:aws:iam::aws:policy/PowerUserAccess"}],
                "Groups": ["DevOps", "Developers"],
            },
            {
                "UserName": "billing-viewer",
                "UserId": "AIDADEMO000000000BILV",
                "Arn": "arn:aws:iam::123456789012:user/billing-viewer",
                "CreateDate": (now - timedelta(days=350)).isoformat(),
                "MFAEnabled": True,
                "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/billing-viewer", "EnableDate": (now - timedelta(days=345)).isoformat()}],
                "AccessKeys": [],
                "AttachedPolicies": [{"PolicyName": "AWSBillingReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/AWSBillingReadOnlyAccess"}],
                "Groups": ["Finance"],
            },
        ]

        return users

    # ------------------------------------------------------------------
    # Public collection methods
    # ------------------------------------------------------------------

    def collect_user_evidence(self) -> list[dict[str, Any]]:
        """Collect IAM user evidence.

        In demo mode, returns simulated data. Otherwise queries the
        AWS IAM API for real user information.
        """
        if self.demo_mode:
            logger.info("Returning demo IAM user evidence (%d users)", 10)
            return self._generate_demo_evidence()

        return self._collect_real_user_evidence()

    def _collect_real_user_evidence(self) -> list[dict[str, Any]]:
        """Query the AWS IAM API and return enriched user records."""
        users: list[dict[str, Any]] = []
        paginator = self.client.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                record: dict[str, Any] = {
                    "UserName": username,
                    "UserId": user["UserId"],
                    "Arn": user["Arn"],
                    "CreateDate": user["CreateDate"].isoformat(),
                }

                # MFA devices
                mfa_resp = self.client.list_mfa_devices(UserName=username)
                mfa_devices = mfa_resp.get("MFADevices", [])
                record["MFAEnabled"] = len(mfa_devices) > 0
                record["MFADevices"] = [
                    {
                        "SerialNumber": d["SerialNumber"],
                        "EnableDate": d["EnableDate"].isoformat(),
                    }
                    for d in mfa_devices
                ]

                # Access keys
                keys_resp = self.client.list_access_keys(UserName=username)
                record["AccessKeys"] = [
                    {
                        "AccessKeyId": k["AccessKeyId"],
                        "Status": k["Status"],
                        "CreateDate": k["CreateDate"].isoformat(),
                    }
                    for k in keys_resp.get("AccessKeyMetadata", [])
                ]

                # Attached policies
                policies_resp = self.client.list_attached_user_policies(UserName=username)
                record["AttachedPolicies"] = [
                    {"PolicyName": p["PolicyName"], "PolicyArn": p["PolicyArn"]}
                    for p in policies_resp.get("AttachedPolicies", [])
                ]

                # Groups
                groups_resp = self.client.list_groups_for_user(UserName=username)
                record["Groups"] = [
                    g["GroupName"] for g in groups_resp.get("Groups", [])
                ]

                users.append(record)

        logger.info("Collected evidence for %d IAM users", len(users))
        return users
