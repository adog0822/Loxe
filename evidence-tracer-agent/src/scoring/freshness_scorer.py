"""
Freshness Scorer

Calculates evidence freshness scores and detects compliance gaps
based on the age and timeliness of collected evidence. Produces a
freshness report that flags stale evidence, upcoming deadlines,
and overall compliance health.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Optional
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from aws_connectors.iam_collector import IAMUser, AccessKey


@dataclass
class FreshnessMetric:
    metric_name: str
    value: float              # 0.0 (stale) to 1.0 (fresh)
    grade: str                # A / B / C / D / F
    details: str = ""


@dataclass
class GapFinding:
    gap_id: str
    severity: str             # CRITICAL / HIGH / MEDIUM / LOW
    category: str
    description: str
    affected_users: list[str] = field(default_factory=list)
    remediation: str = ""
    days_overdue: int = 0


@dataclass
class FreshnessReport:
    generated_at: str
    overall_score: float = 0.0      # 0.0 - 100.0
    overall_grade: str = "F"
    metrics: list[FreshnessMetric] = field(default_factory=list)
    gaps: list[GapFinding] = field(default_factory=list)

    @property
    def critical_gaps(self) -> int:
        return sum(1 for g in self.gaps if g.severity == "CRITICAL")

    @property
    def high_gaps(self) -> int:
        return sum(1 for g in self.gaps if g.severity == "HIGH")


def _score_to_grade(score: float) -> str:
    """Convert a 0-1 score to a letter grade."""
    if score >= 0.9:
        return "A"
    if score >= 0.8:
        return "B"
    if score >= 0.7:
        return "C"
    if score >= 0.6:
        return "D"
    return "F"


def _days_since(iso_timestamp: Optional[str]) -> Optional[int]:
    """Calculate days since an ISO timestamp."""
    if not iso_timestamp:
        return None
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.utcnow()
        return (now - dt.replace(tzinfo=None)).days if not dt.tzinfo else (now - dt).days
    except (ValueError, TypeError):
        return None


class FreshnessScorer:
    """
    Calculates freshness scores and detects compliance gaps from IAM data.

    Scoring dimensions:
    - MFA coverage freshness
    - Access key rotation freshness
    - Password rotation freshness
    - User activity freshness (detecting dormant accounts)
    - Provisioning freshness (detecting orphaned accounts)

    Gap detection:
    - Missing MFA
    - Stale access keys (>90 days)
    - Very stale access keys (>180 days)
    - Dormant accounts
    - Orphaned/inactive accounts with active credentials
    - Password rotation overdue
    """

    KEY_FRESH_DAYS = 30
    KEY_MAX_DAYS = 90
    KEY_CRITICAL_DAYS = 180
    PASSWORD_MAX_DAYS = 90
    DORMANT_DAYS = 60

    def __init__(self):
        self.now = datetime.utcnow()

    def score(self, users: list[IAMUser]) -> FreshnessReport:
        """Calculate freshness scores and detect gaps."""
        report = FreshnessReport(
            generated_at=self.now.isoformat() + "Z",
        )

        if not users:
            return report

        # Calculate each freshness dimension
        mfa_metric = self._score_mfa_freshness(users)
        key_metric = self._score_key_freshness(users)
        pwd_metric = self._score_password_freshness(users)
        activity_metric = self._score_activity_freshness(users)
        provisioning_metric = self._score_provisioning_freshness(users)

        report.metrics = [
            mfa_metric,
            key_metric,
            pwd_metric,
            activity_metric,
            provisioning_metric,
        ]

        # Calculate overall score (weighted average)
        weights = {
            "MFA Coverage": 0.25,
            "Access Key Rotation": 0.25,
            "Password Rotation": 0.15,
            "User Activity": 0.15,
            "Provisioning Hygiene": 0.20,
        }

        total_score = sum(
            m.value * weights.get(m.metric_name, 0.2)
            for m in report.metrics
        )
        report.overall_score = round(total_score * 100, 1)
        report.overall_grade = _score_to_grade(total_score)

        # Detect gaps
        report.gaps = self._detect_gaps(users)

        return report

    def _score_mfa_freshness(self, users: list[IAMUser]) -> FreshnessMetric:
        """Score MFA coverage across all users."""
        if not users:
            return FreshnessMetric("MFA Coverage", 0.0, "F", "No users to evaluate")

        enabled = sum(1 for u in users if u.mfa_enabled)
        ratio = enabled / len(users)

        return FreshnessMetric(
            metric_name="MFA Coverage",
            value=round(ratio, 3),
            grade=_score_to_grade(ratio),
            details=f"{enabled}/{len(users)} users have MFA enabled ({ratio:.0%})",
        )

    def _score_key_freshness(self, users: list[IAMUser]) -> FreshnessMetric:
        """Score access key freshness based on age distribution."""
        all_keys = [k for u in users for k in u.access_keys if k.status == "Active"]

        if not all_keys:
            return FreshnessMetric("Access Key Rotation", 1.0, "A", "No active access keys")

        scores = []
        for key in all_keys:
            age = key.age_days
            if age <= self.KEY_FRESH_DAYS:
                scores.append(1.0)
            elif age <= self.KEY_MAX_DAYS:
                # Linear decay from 1.0 to 0.3
                scores.append(1.0 - 0.7 * (age - self.KEY_FRESH_DAYS) / (self.KEY_MAX_DAYS - self.KEY_FRESH_DAYS))
            elif age <= self.KEY_CRITICAL_DAYS:
                scores.append(0.2)
            else:
                scores.append(0.0)

        avg = sum(scores) / len(scores)
        stale_count = sum(1 for k in all_keys if k.age_days > self.KEY_MAX_DAYS)

        return FreshnessMetric(
            metric_name="Access Key Rotation",
            value=round(avg, 3),
            grade=_score_to_grade(avg),
            details=f"{stale_count}/{len(all_keys)} active keys exceed {self.KEY_MAX_DAYS}-day limit",
        )

    def _score_password_freshness(self, users: list[IAMUser]) -> FreshnessMetric:
        """Score password rotation freshness."""
        users_with_pwd = [u for u in users if u.password_last_changed]

        if not users_with_pwd:
            return FreshnessMetric("Password Rotation", 0.5, "D", "No password data available")

        scores = []
        for u in users_with_pwd:
            days = _days_since(u.password_last_changed)
            if days is None:
                scores.append(0.5)
            elif days <= 30:
                scores.append(1.0)
            elif days <= self.PASSWORD_MAX_DAYS:
                scores.append(1.0 - 0.6 * (days - 30) / (self.PASSWORD_MAX_DAYS - 30))
            else:
                scores.append(0.1)

        avg = sum(scores) / len(scores)
        return FreshnessMetric(
            metric_name="Password Rotation",
            value=round(avg, 3),
            grade=_score_to_grade(avg),
            details=f"Evaluated {len(users_with_pwd)} user password ages",
        )

    def _score_activity_freshness(self, users: list[IAMUser]) -> FreshnessMetric:
        """Score user activity freshness (detecting dormant accounts)."""
        scores = []
        dormant_count = 0

        for u in users:
            last_used = u.password_last_used
            if not last_used:
                # Check access key last used as fallback
                key_dates = [k.last_used_date for k in u.access_keys if k.last_used_date]
                last_used = max(key_dates) if key_dates else None

            days = _days_since(last_used)
            if days is None:
                scores.append(0.3)
                dormant_count += 1
            elif days <= 7:
                scores.append(1.0)
            elif days <= 30:
                scores.append(0.8)
            elif days <= self.DORMANT_DAYS:
                scores.append(0.5)
            else:
                scores.append(0.1)
                dormant_count += 1

        avg = sum(scores) / len(scores) if scores else 0.0
        return FreshnessMetric(
            metric_name="User Activity",
            value=round(avg, 3),
            grade=_score_to_grade(avg),
            details=f"{dormant_count}/{len(users)} accounts appear dormant (>{self.DORMANT_DAYS} days inactive)",
        )

    def _score_provisioning_freshness(self, users: list[IAMUser]) -> FreshnessMetric:
        """Score provisioning hygiene — orphaned accounts, ungrouped users, etc."""
        issues = 0

        # Inactive users with active keys
        orphaned = [
            u for u in users
            if not u.password_last_used
            and any(k.status == "Active" for k in u.access_keys)
        ]
        issues += len(orphaned) * 2  # Double weight

        # Ungrouped users
        ungrouped = [u for u in users if not u.groups]
        issues += len(ungrouped)

        # Calculate score: fewer issues = higher score
        max_possible_issues = len(users) * 3
        score = max(0, 1.0 - (issues / max_possible_issues)) if max_possible_issues else 1.0

        return FreshnessMetric(
            metric_name="Provisioning Hygiene",
            value=round(score, 3),
            grade=_score_to_grade(score),
            details=f"{len(orphaned)} orphaned account(s), {len(ungrouped)} ungrouped user(s)",
        )

    def _detect_gaps(self, users: list[IAMUser]) -> list[GapFinding]:
        """Detect all compliance gaps in IAM data."""
        gaps = []
        gap_counter = 1

        # GAP: Missing MFA
        no_mfa = [u for u in users if not u.mfa_enabled]
        if no_mfa:
            # Check if any are admins (critical)
            admin_no_mfa = [
                u for u in no_mfa
                if any("AdministratorAccess" in p for p in u.attached_policies)
            ]
            if admin_no_mfa:
                gaps.append(GapFinding(
                    gap_id=f"GAP-{gap_counter:03d}",
                    severity="CRITICAL",
                    category="Authentication",
                    description="Admin user(s) without MFA enabled",
                    affected_users=[u.user_name for u in admin_no_mfa],
                    remediation="Enable MFA for all admin users immediately.",
                ))
                gap_counter += 1

            gaps.append(GapFinding(
                gap_id=f"GAP-{gap_counter:03d}",
                severity="HIGH",
                category="Authentication",
                description=f"{len(no_mfa)} user(s) do not have MFA enabled",
                affected_users=[u.user_name for u in no_mfa],
                remediation="Enable MFA for all IAM users. Enforce via SCP or IAM policy.",
            ))
            gap_counter += 1

        # GAP: Very stale access keys (>180 days)
        very_stale = []
        for u in users:
            for k in u.access_keys:
                if k.age_days > self.KEY_CRITICAL_DAYS:
                    very_stale.append((u.user_name, k.age_days))

        if very_stale:
            gaps.append(GapFinding(
                gap_id=f"GAP-{gap_counter:03d}",
                severity="CRITICAL",
                category="Credential Management",
                description=f"{len(very_stale)} access key(s) exceed {self.KEY_CRITICAL_DAYS}-day limit",
                affected_users=[v[0] for v in very_stale],
                remediation="Rotate these keys immediately. Keys this old pose significant compromise risk.",
                days_overdue=max(v[1] - self.KEY_CRITICAL_DAYS for v in very_stale),
            ))
            gap_counter += 1

        # GAP: Stale access keys (>90 days)
        stale = []
        for u in users:
            for k in u.access_keys:
                if self.KEY_MAX_DAYS < k.age_days <= self.KEY_CRITICAL_DAYS:
                    stale.append((u.user_name, k.age_days))

        if stale:
            gaps.append(GapFinding(
                gap_id=f"GAP-{gap_counter:03d}",
                severity="HIGH",
                category="Credential Management",
                description=f"{len(stale)} access key(s) exceed {self.KEY_MAX_DAYS}-day rotation policy",
                affected_users=[s[0] for s in stale],
                remediation="Rotate these access keys within the next 7 days.",
                days_overdue=max(s[1] - self.KEY_MAX_DAYS for s in stale),
            ))
            gap_counter += 1

        # GAP: Orphaned accounts (inactive user with active credentials)
        orphaned = [
            u for u in users
            if not u.password_last_used
            and any(k.status == "Active" for k in u.access_keys)
        ]
        if orphaned:
            gaps.append(GapFinding(
                gap_id=f"GAP-{gap_counter:03d}",
                severity="HIGH",
                category="Account Lifecycle",
                description=f"{len(orphaned)} inactive account(s) retain active credentials",
                affected_users=[u.user_name for u in orphaned],
                remediation="Deactivate credentials for inactive users. Implement offboarding automation.",
            ))
            gap_counter += 1

        # GAP: Over-privileged users
        overprivileged = [
            u for u in users
            if any("AdministratorAccess" in p for p in u.attached_policies)
            and u.tags.get("Role", "") not in ["CTO", "Lead Engineer", "DevOps Engineer"]
        ]
        if overprivileged:
            gaps.append(GapFinding(
                gap_id=f"GAP-{gap_counter:03d}",
                severity="MEDIUM",
                category="Least Privilege",
                description=f"{len(overprivileged)} user(s) may have excessive privileges for their role",
                affected_users=[u.user_name for u in overprivileged],
                remediation="Review and scope down permissions. Apply least-privilege policies.",
            ))
            gap_counter += 1

        return gaps

    def export_report(self, report: FreshnessReport, output_path: str):
        """Export freshness report to JSON."""
        data = {
            "generated_at": report.generated_at,
            "overall_score": report.overall_score,
            "overall_grade": report.overall_grade,
            "critical_gaps": report.critical_gaps,
            "high_gaps": report.high_gaps,
            "metrics": [asdict(m) for m in report.metrics],
            "gaps": [asdict(g) for g in report.gaps],
        }
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
