"""SOC 2 Control Mapper - Maps AWS evidence to SOC 2 Trust Service Criteria."""

from typing import Any

CONTROLS: dict[str, dict[str, Any]] = {
    "CC6.1": {
        "name": "Logical Access",
        "description": (
            "The entity implements logical access security software, infrastructure, "
            "and architectures over protected information assets to protect them from "
            "security events."
        ),
        "aws_services": ["IAM", "SSO", "Directory Service", "Cognito"],
        "evidence_types": [
            "iam_policies",
            "iam_users",
            "iam_roles",
            "mfa_status",
            "password_policy",
        ],
    },
    "CC6.3": {
        "name": "Access Key Management",
        "description": (
            "The entity authorizes, modifies, or removes access to data, software, "
            "functions, and other protected information assets based on roles and "
            "responsibilities."
        ),
        "aws_services": ["IAM", "KMS", "Secrets Manager"],
        "evidence_types": [
            "access_keys",
            "key_rotation",
            "kms_keys",
            "secrets_rotation",
        ],
    },
    "CC6.7": {
        "name": "Least Privilege",
        "description": (
            "The entity restricts the transmission, movement, and removal of "
            "information to authorized internal and external users and processes, "
            "and protects it during transmission."
        ),
        "aws_services": ["IAM", "S3", "VPC", "Security Groups"],
        "evidence_types": [
            "iam_policies",
            "s3_bucket_policies",
            "security_groups",
            "overly_permissive_policies",
        ],
    },
    "CC7.1": {
        "name": "Infrastructure Changes",
        "description": (
            "To meet its objectives, the entity uses detection and monitoring "
            "procedures to identify changes to configurations that result in the "
            "introduction of new vulnerabilities."
        ),
        "aws_services": ["CloudTrail", "Config", "GuardDuty"],
        "evidence_types": [
            "cloudtrail_events",
            "config_rules",
            "guardduty_findings",
            "infrastructure_changes",
        ],
    },
    "CC7.2": {
        "name": "Security Configuration",
        "description": (
            "The entity monitors system components and the operation of those "
            "components for anomalies that are indicative of malicious acts, "
            "natural disasters, and errors."
        ),
        "aws_services": ["Config", "Security Hub", "Inspector"],
        "evidence_types": [
            "config_compliance",
            "security_hub_findings",
            "inspector_findings",
            "baseline_configs",
        ],
    },
    "CC7.4": {
        "name": "Monitoring & Logging",
        "description": (
            "The entity responds to identified security incidents by executing a "
            "defined incident response program to understand, contain, remediate, "
            "and communicate security incidents."
        ),
        "aws_services": ["CloudWatch", "CloudTrail", "VPC Flow Logs", "S3 Access Logs"],
        "evidence_types": [
            "cloudwatch_alarms",
            "log_groups",
            "flow_logs",
            "access_logs",
            "trail_status",
        ],
    },
    "CC8.1": {
        "name": "Change Management",
        "description": (
            "The entity authorizes, designs, develops or acquires, configures, "
            "documents, tests, approves, and implements changes to infrastructure "
            "and software."
        ),
        "aws_services": ["CodePipeline", "CodeDeploy", "CloudFormation", "Config"],
        "evidence_types": [
            "pipeline_executions",
            "deployment_history",
            "stack_changes",
            "change_approvals",
        ],
    },
    "CC8.2": {
        "name": "Data Management",
        "description": (
            "The entity implements policies and procedures to classify, manage, "
            "and protect data during its lifecycle, including storage, processing, "
            "and disposal."
        ),
        "aws_services": ["S3", "RDS", "DynamoDB", "Macie"],
        "evidence_types": [
            "s3_encryption",
            "rds_encryption",
            "backup_configs",
            "data_classification",
            "lifecycle_policies",
        ],
    },
}


class SOC2ControlMapper:
    """Maps collected AWS evidence to SOC 2 controls."""

    def __init__(self) -> None:
        self.controls = CONTROLS

    def get_control(self, control_id: str) -> dict[str, Any] | None:
        """Return the control definition for a given control ID."""
        return self.controls.get(control_id)

    def get_all_control_ids(self) -> list[str]:
        """Return all control IDs."""
        return list(self.controls.keys())

    def map_evidence(self, evidence: dict[str, Any]) -> dict[str, list[str]]:
        """Map evidence items to the SOC 2 controls they satisfy.

        Args:
            evidence: Dictionary with evidence_type keys and evidence data values.

        Returns:
            Dictionary mapping control IDs to lists of matched evidence types.
        """
        mapping: dict[str, list[str]] = {}
        evidence_types_present = set(evidence.keys())

        for control_id, control in self.controls.items():
            matched = evidence_types_present & set(control["evidence_types"])
            if matched:
                mapping[control_id] = sorted(matched)

        return mapping

    def get_coverage_summary(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """Return a coverage summary showing which controls are covered vs gaps.

        Args:
            evidence: Dictionary with evidence_type keys and evidence data values.

        Returns:
            Summary with covered controls, gaps, and coverage percentage.
        """
        mapping = self.map_evidence(evidence)
        all_ids = self.get_all_control_ids()
        covered = [cid for cid in all_ids if cid in mapping]
        gaps = [cid for cid in all_ids if cid not in mapping]

        return {
            "total_controls": len(all_ids),
            "covered_count": len(covered),
            "gap_count": len(gaps),
            "coverage_pct": round(len(covered) / len(all_ids) * 100, 1),
            "covered": {cid: mapping[cid] for cid in covered},
            "gaps": {
                cid: {
                    "name": self.controls[cid]["name"],
                    "missing_evidence": self.controls[cid]["evidence_types"],
                }
                for cid in gaps
            },
        }
