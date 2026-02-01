"""Freshness and gap detection scoring for SOC 2 evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any

from src.evidence_collectors.base import Evidence
from src.soc2_mapping.control_mapper import ControlCoverage


@dataclass
class FreshnessResult:
    evidence_type: str
    source: str
    collected_at: str
    age_hours: float
    freshness_score: float  # 0-100
    status: str  # fresh, aging, stale

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_type": self.evidence_type,
            "source": self.source,
            "collected_at": self.collected_at,
            "age_hours": round(self.age_hours, 1),
            "freshness_score": round(self.freshness_score, 1),
            "status": self.status,
        }


@dataclass
class GapResult:
    control_id: str
    gap_type: str  # missing_evidence, stale_evidence, low_coverage
    severity: str  # critical, high, medium, low
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "gap_type": self.gap_type,
            "severity": self.severity,
            "detail": self.detail,
        }


class FreshnessScorer:
    """Scores evidence freshness and detects compliance gaps."""

    # Thresholds in hours
    FRESH_THRESHOLD = 24
    AGING_THRESHOLD = 72

    def score_freshness(self, evidence_items: list[Evidence]) -> list[FreshnessResult]:
        now = datetime.now(timezone.utc)
        results: list[FreshnessResult] = []

        for ev in evidence_items:
            collected = _parse_iso(ev.collected_at)
            if collected is None:
                results.append(
                    FreshnessResult(
                        evidence_type=ev.evidence_type,
                        source=ev.source,
                        collected_at=ev.collected_at,
                        age_hours=0,
                        freshness_score=0,
                        status="stale",
                    )
                )
                continue

            age = now - collected
            age_hours = age.total_seconds() / 3600

            if age_hours <= self.FRESH_THRESHOLD:
                score = 100 - (age_hours / self.FRESH_THRESHOLD) * 20
                status = "fresh"
            elif age_hours <= self.AGING_THRESHOLD:
                score = 80 - (
                    (age_hours - self.FRESH_THRESHOLD)
                    / (self.AGING_THRESHOLD - self.FRESH_THRESHOLD)
                ) * 40
                status = "aging"
            else:
                score = max(0, 40 - (age_hours - self.AGING_THRESHOLD) / 24 * 5)
                status = "stale"

            results.append(
                FreshnessResult(
                    evidence_type=ev.evidence_type,
                    source=ev.source,
                    collected_at=ev.collected_at,
                    age_hours=age_hours,
                    freshness_score=round(score, 1),
                    status=status,
                )
            )
        return results

    def detect_gaps(
        self,
        coverages: list[ControlCoverage],
        freshness_results: list[FreshnessResult],
    ) -> list[GapResult]:
        gaps: list[GapResult] = []
        stale_types = {
            fr.evidence_type for fr in freshness_results if fr.status == "stale"
        }

        for cov in coverages:
            # Missing evidence
            if cov.evidence_missing:
                severity = "critical" if cov.coverage_pct < 50 else "high"
                gaps.append(
                    GapResult(
                        control_id=cov.control.control_id,
                        gap_type="missing_evidence",
                        severity=severity,
                        detail=(
                            f"Missing evidence for {cov.control.title}: "
                            f"{', '.join(cov.evidence_missing)}"
                        ),
                    )
                )

            # Stale evidence
            stale_for_control = [
                et for et in cov.evidence_present if et in stale_types
            ]
            if stale_for_control:
                gaps.append(
                    GapResult(
                        control_id=cov.control.control_id,
                        gap_type="stale_evidence",
                        severity="medium",
                        detail=(
                            f"Stale evidence for {cov.control.title}: "
                            f"{', '.join(stale_for_control)}"
                        ),
                    )
                )

            # Low coverage
            if 0 < cov.coverage_pct < 50:
                gaps.append(
                    GapResult(
                        control_id=cov.control.control_id,
                        gap_type="low_coverage",
                        severity="high",
                        detail=(
                            f"{cov.control.title} has only "
                            f"{cov.coverage_pct}% evidence coverage"
                        ),
                    )
                )

        return gaps

    def overall_score(
        self,
        freshness_results: list[FreshnessResult],
        coverages: list[ControlCoverage],
    ) -> dict[str, Any]:
        gaps = self.detect_gaps(coverages, freshness_results)

        avg_freshness = (
            round(
                sum(fr.freshness_score for fr in freshness_results)
                / len(freshness_results),
                1,
            )
            if freshness_results
            else 0.0
        )
        avg_coverage = (
            round(sum(c.coverage_pct for c in coverages) / len(coverages), 1)
            if coverages
            else 0.0
        )
        # Composite: 60% coverage + 40% freshness
        composite = round(avg_coverage * 0.6 + avg_freshness * 0.4, 1)

        critical_gaps = sum(1 for g in gaps if g.severity == "critical")
        high_gaps = sum(1 for g in gaps if g.severity == "high")

        if composite >= 90 and critical_gaps == 0:
            readiness = "AUDIT_READY"
        elif composite >= 70 and critical_gaps == 0:
            readiness = "NEEDS_ATTENTION"
        else:
            readiness = "NOT_READY"

        return {
            "composite_score": composite,
            "average_freshness": avg_freshness,
            "average_coverage": avg_coverage,
            "readiness": readiness,
            "gap_summary": {
                "total": len(gaps),
                "critical": critical_gaps,
                "high": high_gaps,
                "medium": sum(1 for g in gaps if g.severity == "medium"),
                "low": sum(1 for g in gaps if g.severity == "low"),
            },
            "freshness": [fr.to_dict() for fr in freshness_results],
            "gaps": [g.to_dict() for g in gaps],
        }


def _parse_iso(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None
