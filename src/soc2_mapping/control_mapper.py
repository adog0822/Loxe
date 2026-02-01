"""Maps collected evidence to SOC 2 controls and identifies coverage gaps."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.evidence_collectors.base import Evidence
from src.soc2_mapping.controls import ALL_CONTROLS, ControlDefinition


@dataclass
class ControlCoverage:
    control: ControlDefinition
    evidence_present: list[str]
    evidence_missing: list[str]
    coverage_pct: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control.control_id,
            "title": self.control.title,
            "category": self.control.category,
            "description": self.control.description,
            "evidence_present": self.evidence_present,
            "evidence_missing": self.evidence_missing,
            "coverage_pct": self.coverage_pct,
        }


class ControlMapper:
    """Maps evidence items to SOC 2 controls and computes coverage."""

    def __init__(self, controls: dict[str, ControlDefinition] | None = None) -> None:
        self.controls = controls or ALL_CONTROLS

    def map(self, evidence_items: list[Evidence]) -> list[ControlCoverage]:
        # Build a set of all evidence types that were successfully collected
        collected_types: set[str] = set()
        for ev in evidence_items:
            collected_types.add(ev.evidence_type)

        results: list[ControlCoverage] = []
        for ctrl in self.controls.values():
            present = [
                et for et in ctrl.required_evidence if et in collected_types
            ]
            missing = [
                et for et in ctrl.required_evidence if et not in collected_types
            ]
            total = len(ctrl.required_evidence)
            pct = round(len(present) / total * 100, 1) if total else 0.0
            results.append(
                ControlCoverage(
                    control=ctrl,
                    evidence_present=present,
                    evidence_missing=missing,
                    coverage_pct=pct,
                )
            )
        return results

    def summary(self, coverages: list[ControlCoverage]) -> dict[str, Any]:
        full_coverage = sum(1 for c in coverages if c.coverage_pct == 100.0)
        partial = sum(1 for c in coverages if 0 < c.coverage_pct < 100.0)
        no_coverage = sum(1 for c in coverages if c.coverage_pct == 0.0)
        avg_pct = (
            round(sum(c.coverage_pct for c in coverages) / len(coverages), 1)
            if coverages
            else 0.0
        )
        return {
            "total_controls": len(coverages),
            "full_coverage": full_coverage,
            "partial_coverage": partial,
            "no_coverage": no_coverage,
            "average_coverage_pct": avg_pct,
            "controls": [c.to_dict() for c in coverages],
        }
