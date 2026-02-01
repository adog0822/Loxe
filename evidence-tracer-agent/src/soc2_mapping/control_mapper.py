"""
SOC 2 Control Mapper

Maps AWS IAM evidence to all 8 SOC 2 Trust Services Criteria (TSC) control
families. Evaluates each control against collected IAM data and produces
pass/fail/warning findings with evidence references.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from aws_connectors.iam_collector import IAMUser


# ── SOC 2 Trust Services Criteria ────────────────────────────────────────

@dataclass
class ControlCheck:
    check_id: str
    description: str
    status: str = "PASS"    # PASS / FAIL / WARNING
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class SOC2Control:
    control_id: str
    control_name: str
    category: str           # CC (Common Criteria) family
    description: str
    checks: list[ControlCheck] = field(default_factory=list)

    @property
    def status(self) -> str:
        """Overall status: FAIL if any check fails, WARNING if any warns, else PASS."""
        statuses = [c.status for c in self.checks]
        if "FAIL" in statuses:
            return "FAIL"
        if "WARNING" in statuses:
            return "WARNING"
        return "PASS"


@dataclass
class SOC2Report:
    generated_at: str
    account_id: str
    controls: list[SOC2Control] = field(default_factory=list)

    @property
    def total_controls(self) -> int:
        return len(self.controls)

    @property
    def passing(self) -> int:
        return sum(1 for c in self.controls if c.status == "PASS")

    @property
    def failing(self) -> int:
        return sum(1 for c in self.controls if c.status == "FAIL")

    @property
    def warnings(self) -> int:
        return sum(1 for c in self.controls if c.status == "WARNING")


# ── Control Definitions ─────────────────────────────────────────────────

CONTROL_DEFINITIONS = [
    {
        "id": "CC6.1",
        "name": "Logical and Physical Access Controls",
        "category": "CC6 - Logical and Physical Access",
        "description": "The entity implements logical access security measures to protect against unauthorized access to information assets.",
    },
    {
        "id": "CC6.2",
        "name": "User Authentication and Access Provisioning",
        "category": "CC6 - Logical and Physical Access",
        "description": "Prior to issuing system credentials, the entity registers and authorizes new users. Access credentials are removed when user access is no longer authorized.",
    },
    {
        "id": "CC6.3",
        "name": "Role-Based Access and Least Privilege",
        "category": "CC6 - Logical and Physical Access",
        "description": "The entity authorizes, modifies, or removes access to data and systems based on roles and the principle of least privilege.",
    },
    {
        "id": "CC6.6",
        "name": "Multi-Factor Authentication",
        "category": "CC6 - Logical and Physical Access",
        "description": "The entity implements multi-factor authentication for access to systems and sensitive data.",
    },
    {
        "id": "CC6.7",
        "name": "Access Key Rotation and Credential Management",
        "category": "CC6 - Logical and Physical Access",
        "description": "The entity manages credentials including periodic rotation, disabling unused credentials, and monitoring for compromise.",
    },
    {
        "id": "CC6.8",
        "name": "Separation of Duties",
        "category": "CC6 - Logical and Physical Access",
        "description": "The entity implements separation of duties to prevent unauthorized or unintended actions.",
    },
    {
        "id": "CC7.1",
        "name": "Security Monitoring and Logging",
        "category": "CC7 - System Operations",
        "description": "The entity monitors system components and detects anomalies that are indicative of malicious acts or other events.",
    },
    {
        "id": "CC7.2",
        "name": "Incident Response and Anomaly Detection",
        "category": "CC7 - System Operations",
        "description": "The entity monitors system activity to identify and respond to security incidents in a timely manner.",
    },
]


class SOC2ControlMapper:
    """
    Maps AWS IAM evidence to SOC 2 controls.

    Evaluates all 8 defined controls against IAM user data and
    produces a SOC2Report with pass/fail/warning findings.
    """

    KEY_MAX_AGE_DAYS = 90
    KEY_WARNING_AGE_DAYS = 60
    MFA_REQUIRED_THRESHOLD = 1.0    # 100% of users must have MFA
    ADMIN_MAX_COUNT = 3             # Max users with admin access

    def __init__(self, account_id: str = "123456789012"):
        self.account_id = account_id

    def evaluate(self, users: list[IAMUser]) -> SOC2Report:
        """Run all SOC 2 control checks against IAM user data."""
        report = SOC2Report(
            generated_at=datetime.utcnow().isoformat() + "Z",
            account_id=self.account_id,
        )

        for ctrl_def in CONTROL_DEFINITIONS:
            control = SOC2Control(
                control_id=ctrl_def["id"],
                control_name=ctrl_def["name"],
                category=ctrl_def["category"],
                description=ctrl_def["description"],
            )

            # Dispatch to the correct evaluator
            evaluator = self._get_evaluator(ctrl_def["id"])
            if evaluator:
                checks = evaluator(users)
                control.checks = checks

            report.controls.append(control)

        return report

    def _get_evaluator(self, control_id: str):
        """Return the evaluator function for a control ID."""
        evaluators = {
            "CC6.1": self._check_cc6_1,
            "CC6.2": self._check_cc6_2,
            "CC6.3": self._check_cc6_3,
            "CC6.6": self._check_cc6_6,
            "CC6.7": self._check_cc6_7,
            "CC6.8": self._check_cc6_8,
            "CC7.1": self._check_cc7_1,
            "CC7.2": self._check_cc7_2,
        }
        return evaluators.get(control_id)

    # ── CC6.1: Logical Access Controls ───────────────────────────────

    def _check_cc6_1(self, users: list[IAMUser]) -> list[ControlCheck]:
        checks = []

        # Check: All users have password policies
        users_with_pwd = [u for u in users if u.password_last_changed]
        check = ControlCheck(
            check_id="CC6.1-01",
            description="All users have managed passwords with rotation",
            evidence=[f"{len(users_with_pwd)}/{len(users)} users have password management configured"],
        )
        if len(users_with_pwd) == len(users):
            check.status = "PASS"
        elif len(users_with_pwd) >= len(users) * 0.9:
            check.status = "WARNING"
            check.remediation = "Ensure all user accounts have password policies enforced."
        else:
            check.status = "FAIL"
            check.remediation = "Multiple users lack password management. Enable and enforce password policies for all IAM users."
        checks.append(check)

        # Check: No users with both console and programmatic access without justification
        users_with_both = [u for u in users if u.password_last_used and u.access_keys]
        check2 = ControlCheck(
            check_id="CC6.1-02",
            description="Users with both console and API access are tracked",
            evidence=[
                f"{len(users_with_both)} users have both console and programmatic access",
                f"Users: {', '.join(u.user_name for u in users_with_both[:5])}",
            ],
        )
        check2.status = "PASS" if len(users_with_both) <= len(users) * 0.7 else "WARNING"
        if check2.status == "WARNING":
            check2.remediation = "Review users with dual access. Restrict to single access type where possible."
        checks.append(check2)

        return checks

    # ── CC6.2: User Provisioning / Deprovisioning ────────────────────

    def _check_cc6_2(self, users: list[IAMUser]) -> list[ControlCheck]:
        checks = []

        # Check: No inactive users with active credentials
        inactive_with_creds = [
            u for u in users
            if not u.password_last_used
            and any(k.status == "Active" for k in u.access_keys)
        ]
        check = ControlCheck(
            check_id="CC6.2-01",
            description="Inactive users do not retain active credentials",
            evidence=[
                f"{len(inactive_with_creds)} inactive user(s) still have active access keys",
            ],
        )
        if inactive_with_creds:
            check.status = "FAIL"
            check.evidence.append(f"Affected users: {', '.join(u.user_name for u in inactive_with_creds)}")
            check.remediation = "Immediately deactivate access keys for inactive users. Implement automated deprovisioning."
        else:
            check.status = "PASS"
        checks.append(check)

        # Check: All users are assigned to groups
        ungrouped = [u for u in users if not u.groups]
        check2 = ControlCheck(
            check_id="CC6.2-02",
            description="All users are assigned to at least one group",
            evidence=[f"{len(ungrouped)} user(s) have no group membership"],
        )
        check2.status = "PASS" if not ungrouped else "WARNING"
        if ungrouped:
            check2.evidence.append(f"Ungrouped: {', '.join(u.user_name for u in ungrouped)}")
            check2.remediation = "Assign all users to appropriate groups for consistent policy management."
        checks.append(check2)

        return checks

    # ── CC6.3: Least Privilege ───────────────────────────────────────

    def _check_cc6_3(self, users: list[IAMUser]) -> list[ControlCheck]:
        checks = []

        admin_users = [
            u for u in users
            if any("AdministratorAccess" in p for p in u.attached_policies)
        ]
        check = ControlCheck(
            check_id="CC6.3-01",
            description=f"Administrative access is limited (max {self.ADMIN_MAX_COUNT} users)",
            evidence=[
                f"{len(admin_users)} user(s) have AdministratorAccess",
                f"Admin users: {', '.join(u.user_name for u in admin_users)}",
            ],
        )
        if len(admin_users) <= self.ADMIN_MAX_COUNT:
            check.status = "PASS"
        else:
            check.status = "FAIL"
            check.remediation = f"Reduce admin users to {self.ADMIN_MAX_COUNT} or fewer. Apply scoped policies instead."
        checks.append(check)

        # Check: Users have role-appropriate policies
        overprivileged = [
            u for u in users
            if any("AdministratorAccess" in p or "PowerUserAccess" in p for p in u.attached_policies)
            and u.tags.get("Role", "") not in ["CTO", "Lead Engineer", "DevOps Engineer"]
        ]
        check2 = ControlCheck(
            check_id="CC6.3-02",
            description="Users have role-appropriate access levels",
            evidence=[f"{len(overprivileged)} potentially over-privileged user(s) detected"],
        )
        if not overprivileged:
            check2.status = "PASS"
        else:
            check2.status = "WARNING"
            check2.evidence.append(f"Review: {', '.join(u.user_name for u in overprivileged)}")
            check2.remediation = "Review and scope down permissions for users with broad access that doesn't match their role."
        checks.append(check2)

        return checks

    # ── CC6.6: Multi-Factor Authentication ───────────────────────────

    def _check_cc6_6(self, users: list[IAMUser]) -> list[ControlCheck]:
        checks = []

        mfa_enabled = [u for u in users if u.mfa_enabled]
        mfa_disabled = [u for u in users if not u.mfa_enabled]
        coverage = len(mfa_enabled) / len(users) if users else 0

        check = ControlCheck(
            check_id="CC6.6-01",
            description="MFA is enabled for all IAM users",
            evidence=[
                f"MFA coverage: {len(mfa_enabled)}/{len(users)} ({coverage:.0%})",
            ],
        )
        if coverage >= self.MFA_REQUIRED_THRESHOLD:
            check.status = "PASS"
        else:
            check.status = "FAIL"
            check.evidence.append(f"Users without MFA: {', '.join(u.user_name for u in mfa_disabled)}")
            check.remediation = "Enable MFA for all IAM users immediately. Enforce MFA via IAM policy conditions."
        checks.append(check)

        # Check: Admin users specifically must have MFA
        admin_no_mfa = [
            u for u in users
            if any("AdministratorAccess" in p for p in u.attached_policies)
            and not u.mfa_enabled
        ]
        check2 = ControlCheck(
            check_id="CC6.6-02",
            description="All admin users have MFA enabled",
            evidence=[f"{len(admin_no_mfa)} admin user(s) lack MFA"],
        )
        check2.status = "PASS" if not admin_no_mfa else "FAIL"
        if admin_no_mfa:
            check2.evidence.append(f"CRITICAL: {', '.join(u.user_name for u in admin_no_mfa)}")
            check2.remediation = "URGENT: Enable MFA for admin users immediately. This is a critical security gap."
        checks.append(check2)

        return checks

    # ── CC6.7: Credential Rotation ───────────────────────────────────

    def _check_cc6_7(self, users: list[IAMUser]) -> list[ControlCheck]:
        checks = []

        stale_keys = []
        warning_keys = []
        for u in users:
            for k in u.access_keys:
                if k.age_days > self.KEY_MAX_AGE_DAYS:
                    stale_keys.append((u.user_name, k.access_key_id, k.age_days))
                elif k.age_days > self.KEY_WARNING_AGE_DAYS:
                    warning_keys.append((u.user_name, k.access_key_id, k.age_days))

        check = ControlCheck(
            check_id="CC6.7-01",
            description=f"Access keys are rotated within {self.KEY_MAX_AGE_DAYS} days",
            evidence=[
                f"{len(stale_keys)} access key(s) exceed {self.KEY_MAX_AGE_DAYS}-day rotation policy",
                f"{len(warning_keys)} access key(s) approaching rotation deadline",
            ],
        )
        if stale_keys:
            check.status = "FAIL"
            for user, key_id, age in stale_keys:
                check.evidence.append(f"  {user}: {key_id} ({age} days old)")
            check.remediation = "Rotate all stale access keys immediately. Implement automated key rotation."
        elif warning_keys:
            check.status = "WARNING"
            check.remediation = "Schedule key rotation for keys approaching the 90-day limit."
        else:
            check.status = "PASS"
        checks.append(check)

        return checks

    # ── CC6.8: Separation of Duties ──────────────────────────────────

    def _check_cc6_8(self, users: list[IAMUser]) -> list[ControlCheck]:
        checks = []

        # Check: Users in both security and development groups
        conflicting = [
            u for u in users
            if any("Security" in g for g in u.groups)
            and any("Developer" in g or "SRE" in g for g in u.groups)
        ]

        check = ControlCheck(
            check_id="CC6.8-01",
            description="No users have conflicting security and development roles",
            evidence=[f"{len(conflicting)} user(s) have potentially conflicting group memberships"],
        )
        if not conflicting:
            check.status = "PASS"
        else:
            check.status = "WARNING"
            check.evidence.append(f"Users with dual roles: {', '.join(u.user_name for u in conflicting)}")
            check.remediation = "Review dual-role users. Ensure security review functions are independent of development."
        checks.append(check)

        return checks

    # ── CC7.1: Security Monitoring ───────────────────────────────────

    def _check_cc7_1(self, users: list[IAMUser]) -> list[ControlCheck]:
        checks = []

        # Check: Access key usage is being tracked (all keys have last_used data)
        untracked = []
        for u in users:
            for k in u.access_keys:
                if k.status == "Active" and not k.last_used_date:
                    untracked.append(u.user_name)

        check = ControlCheck(
            check_id="CC7.1-01",
            description="Access key usage is monitored and tracked",
            evidence=[
                f"{len(untracked)} active key(s) have no usage tracking data",
                "CloudTrail and access key last-used metadata should be enabled",
            ],
        )
        check.status = "PASS" if not untracked else "WARNING"
        if untracked:
            check.remediation = "Enable CloudTrail logging and review access key usage patterns."
        checks.append(check)

        return checks

    # ── CC7.2: Incident Detection ────────────────────────────────────

    def _check_cc7_2(self, users: list[IAMUser]) -> list[ControlCheck]:
        checks = []

        # Check: No unused active access keys (never used = potential anomaly)
        never_used = []
        for u in users:
            for k in u.access_keys:
                if k.status == "Active" and not k.last_used_date:
                    never_used.append(u.user_name)

        check = ControlCheck(
            check_id="CC7.2-01",
            description="No active credentials exist without recorded usage",
            evidence=[f"{len(never_used)} active credential(s) have never been used"],
        )
        if never_used:
            check.status = "WARNING"
            check.remediation = "Investigate unused active credentials. Disable if not needed."
        else:
            check.status = "PASS"
        checks.append(check)

        # Check: Privileged accounts have recent activity (not dormant)
        dormant_admins = []
        for u in users:
            is_admin = any("AdministratorAccess" in p for p in u.attached_policies)
            if is_admin and not u.password_last_used:
                dormant_admins.append(u.user_name)

        check2 = ControlCheck(
            check_id="CC7.2-02",
            description="Privileged accounts show recent legitimate activity",
            evidence=[f"{len(dormant_admins)} admin account(s) appear dormant"],
        )
        check2.status = "PASS" if not dormant_admins else "WARNING"
        if dormant_admins:
            check2.evidence.append(f"Dormant admins: {', '.join(dormant_admins)}")
            check2.remediation = "Review dormant admin accounts. Disable if no longer needed."
        checks.append(check2)

        return checks

    def export_report(self, report: SOC2Report, output_path: str):
        """Export SOC 2 report to JSON."""
        data = {
            "generated_at": report.generated_at,
            "account_id": report.account_id,
            "summary": {
                "total_controls": report.total_controls,
                "passing": report.passing,
                "failing": report.failing,
                "warnings": report.warnings,
            },
            "controls": [],
        }
        for ctrl in report.controls:
            ctrl_data = {
                "control_id": ctrl.control_id,
                "control_name": ctrl.control_name,
                "category": ctrl.category,
                "description": ctrl.description,
                "status": ctrl.status,
                "checks": [asdict(c) for c in ctrl.checks],
            }
            data["controls"].append(ctrl_data)

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
