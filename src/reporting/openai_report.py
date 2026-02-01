"""Auditor-ready report generation using OpenAI."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from openai import OpenAI


_SYSTEM_PROMPT = """\
You are a SOC 2 compliance auditor assistant. Given evidence data, control \
coverage mapping, and scoring results, produce a concise, professional \
auditor-ready report.

The report should include:
1. Executive Summary – overall readiness, composite score, critical findings
2. Control Coverage Analysis – per-control status, evidence present/missing
3. Freshness Assessment – evidence age, staleness concerns
4. Gap Analysis – prioritized list of compliance gaps with remediation guidance
5. Recommendations – actionable steps ordered by priority

Use clear section headers. Be factual and specific. Reference control IDs \
(e.g., CC6.1) directly. Format as Markdown."""


class ReportGenerator:
    """Generates SOC 2 audit reports using OpenAI."""

    def __init__(self, model: str = "gpt-4o") -> None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def generate(
        self,
        coverage_summary: dict[str, Any],
        scoring_summary: dict[str, Any],
        evidence_items: list[dict[str, Any]] | None = None,
    ) -> str:
        user_content = self._build_prompt(
            coverage_summary, scoring_summary, evidence_items
        )
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            temperature=0.2,
            max_tokens=4096,
        )
        return response.choices[0].message.content or ""

    def generate_and_save(
        self,
        coverage_summary: dict[str, Any],
        scoring_summary: dict[str, Any],
        evidence_items: list[dict[str, Any]] | None = None,
        output_dir: str = "reports",
    ) -> str:
        report_md = self.generate(coverage_summary, scoring_summary, evidence_items)
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(output_dir, f"soc2_report_{timestamp}.md")
        with open(filepath, "w") as f:
            f.write(report_md)
        return filepath

    @staticmethod
    def _build_prompt(
        coverage_summary: dict[str, Any],
        scoring_summary: dict[str, Any],
        evidence_items: list[dict[str, Any]] | None,
    ) -> str:
        sections = [
            "# SOC 2 Evidence Data for Report Generation",
            "",
            "## Scoring Summary",
            f"Composite Score: {scoring_summary.get('composite_score')}/100",
            f"Readiness: {scoring_summary.get('readiness')}",
            f"Average Freshness: {scoring_summary.get('average_freshness')}/100",
            f"Average Coverage: {scoring_summary.get('average_coverage')}%",
            "",
            "### Gap Summary",
            json.dumps(scoring_summary.get("gap_summary", {}), indent=2),
            "",
            "### Detailed Gaps",
            json.dumps(scoring_summary.get("gaps", []), indent=2),
            "",
            "## Control Coverage",
            json.dumps(coverage_summary, indent=2),
        ]

        if evidence_items:
            # Include a condensed summary of evidence for context
            condensed = []
            for ev in evidence_items:
                condensed.append(
                    {
                        "source": ev.get("source"),
                        "type": ev.get("evidence_type"),
                        "collected_at": ev.get("collected_at"),
                        "controls": ev.get("controls"),
                        # Include top-level stats only, skip large nested data
                        "stats": {
                            k: v
                            for k, v in ev.get("data", {}).items()
                            if not isinstance(v, list)
                        },
                    }
                )
            sections.extend(
                [
                    "",
                    "## Evidence Summary",
                    json.dumps(condensed, indent=2),
                ]
            )

        return "\n".join(sections)
