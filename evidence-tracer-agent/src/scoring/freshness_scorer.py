"""Freshness Scorer - Scores evidence freshness and detects control gaps."""

from datetime import datetime, timezone
from typing import Any

from src.soc2_mapping.control_mapper import SOC2ControlMapper


class FreshnessScorer:
    """Scores evidence based on age/freshness and identifies control coverage gaps."""

    # Thresholds in hours for freshness scoring
    FRESH_THRESHOLD_HOURS = 24
    ACCEPTABLE_THRESHOLD_HOURS = 72
    STALE_THRESHOLD_HOURS = 168  # 7 days

    def __init__(self) -> None:
        self.mapper = SOC2ControlMapper()

    def calculate_scores(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """Calculate freshness and gap detection scores for collected evidence.

        Args:
            evidence: Dictionary with evidence_type keys and evidence data values.
                      Each value should have a 'collected_at' ISO timestamp.

        Returns:
            Dictionary containing:
              - freshness_score: 0-100 overall freshness rating
              - gap_score: 0-100 control coverage rating
              - details: per-evidence-type freshness breakdown
              - coverage: SOC 2 control coverage summary
        """
        freshness_details = self._score_freshness(evidence)
        coverage = self.mapper.get_coverage_summary(evidence)

        # Overall freshness is the average of individual scores
        individual_scores = [d["score"] for d in freshness_details.values()]
        freshness_score = (
            round(sum(individual_scores) / len(individual_scores), 1)
            if individual_scores
            else 0.0
        )

        # Gap score is simply the coverage percentage
        gap_score = coverage["coverage_pct"]

        return {
            "freshness_score": freshness_score,
            "gap_score": gap_score,
            "freshness_details": freshness_details,
            "coverage": coverage,
        }

    def _score_freshness(self, evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Score each evidence type based on when it was collected.

        Returns:
            Mapping of evidence_type -> {score, age_hours, label}.
        """
        now = datetime.now(timezone.utc)
        details: dict[str, dict[str, Any]] = {}

        for evidence_type, data in evidence.items():
            collected_at_str = None
            if isinstance(data, dict):
                collected_at_str = data.get("collected_at")

            if not collected_at_str:
                details[evidence_type] = {
                    "score": 0.0,
                    "age_hours": None,
                    "label": "unknown",
                }
                continue

            collected_at = datetime.fromisoformat(collected_at_str)
            age_hours = (now - collected_at).total_seconds() / 3600.0

            score = self._hours_to_score(age_hours)
            label = self._hours_to_label(age_hours)

            details[evidence_type] = {
                "score": score,
                "age_hours": round(age_hours, 1),
                "label": label,
            }

        return details

    def _hours_to_score(self, age_hours: float) -> float:
        """Convert evidence age in hours to a 0-100 freshness score."""
        if age_hours <= self.FRESH_THRESHOLD_HOURS:
            return 100.0
        if age_hours <= self.ACCEPTABLE_THRESHOLD_HOURS:
            # Linear decay from 100 to 70
            ratio = (age_hours - self.FRESH_THRESHOLD_HOURS) / (
                self.ACCEPTABLE_THRESHOLD_HOURS - self.FRESH_THRESHOLD_HOURS
            )
            return round(100.0 - (30.0 * ratio), 1)
        if age_hours <= self.STALE_THRESHOLD_HOURS:
            # Linear decay from 70 to 30
            ratio = (age_hours - self.ACCEPTABLE_THRESHOLD_HOURS) / (
                self.STALE_THRESHOLD_HOURS - self.ACCEPTABLE_THRESHOLD_HOURS
            )
            return round(70.0 - (40.0 * ratio), 1)
        # Beyond stale threshold: decay from 30 toward 0
        extra = age_hours - self.STALE_THRESHOLD_HOURS
        return max(0.0, round(30.0 - (extra / 24.0), 1))

    def _hours_to_label(self, age_hours: float) -> str:
        """Convert evidence age in hours to a human-readable label."""
        if age_hours <= self.FRESH_THRESHOLD_HOURS:
            return "fresh"
        if age_hours <= self.ACCEPTABLE_THRESHOLD_HOURS:
            return "acceptable"
        if age_hours <= self.STALE_THRESHOLD_HOURS:
            return "stale"
        return "expired"
