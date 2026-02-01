"""SOC 2 Evidence Tracer – main entry point.

Orchestrates evidence collection, control mapping, scoring, and report
generation for SOC 2 compliance audits.

Usage:
    python -m src.main [--skip-report] [--output-dir DIR]

Environment variables:
    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION
    OPENAI_API_KEY  (required unless --skip-report)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone

from dotenv import load_dotenv

from src.evidence_collectors.iam_collector import IAMEvidenceCollector
from src.evidence_collectors.cloudtrail_collector import CloudTrailEvidenceCollector
from src.evidence_collectors.guardduty_collector import GuardDutyEvidenceCollector
from src.soc2_mapping.control_mapper import ControlMapper
from src.scoring.freshness import FreshnessScorer
from src.reporting.openai_report import ReportGenerator

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("evidence_tracer")


def collect_evidence():
    """Run all evidence collectors and return combined results."""
    collectors = [
        ("IAM", IAMEvidenceCollector),
        ("CloudTrail", CloudTrailEvidenceCollector),
        ("GuardDuty", GuardDutyEvidenceCollector),
    ]
    all_evidence = []
    for name, cls in collectors:
        log.info("Collecting %s evidence...", name)
        try:
            collector = cls()
            evidence = collector.collect()
            all_evidence.extend(evidence)
            log.info("  Collected %d evidence items from %s", len(evidence), name)
        except Exception:
            log.exception("  Failed to collect %s evidence", name)
    return all_evidence


def run_pipeline(skip_report: bool = False, output_dir: str = "reports"):
    """Execute the full evidence-collection-to-report pipeline."""

    # 1. Collect evidence
    log.info("=== Phase 1: Evidence Collection ===")
    evidence_items = collect_evidence()
    if not evidence_items:
        log.error("No evidence collected. Check AWS credentials and permissions.")
        sys.exit(1)
    log.info("Total evidence items collected: %d", len(evidence_items))

    # 2. Map to SOC 2 controls
    log.info("=== Phase 2: SOC 2 Control Mapping ===")
    mapper = ControlMapper()
    coverages = mapper.map(evidence_items)
    coverage_summary = mapper.summary(coverages)
    log.info(
        "Control coverage: %d/%d fully covered",
        coverage_summary["full_coverage"],
        coverage_summary["total_controls"],
    )

    # 3. Score freshness and detect gaps
    log.info("=== Phase 3: Freshness & Gap Scoring ===")
    scorer = FreshnessScorer()
    freshness_results = scorer.score_freshness(evidence_items)
    scoring_summary = scorer.overall_score(freshness_results, coverages)
    log.info("Composite score: %s/100", scoring_summary["composite_score"])
    log.info("Readiness: %s", scoring_summary["readiness"])
    log.info(
        "Gaps: %d total (%d critical, %d high)",
        scoring_summary["gap_summary"]["total"],
        scoring_summary["gap_summary"]["critical"],
        scoring_summary["gap_summary"]["high"],
    )

    # 4. Save raw results as JSON
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    raw_path = os.path.join(output_dir, f"evidence_raw_{timestamp}.json")
    with open(raw_path, "w") as f:
        json.dump(
            {
                "evidence": [e.to_dict() for e in evidence_items],
                "coverage": coverage_summary,
                "scoring": scoring_summary,
            },
            f,
            indent=2,
            default=str,
        )
    log.info("Raw results saved to %s", raw_path)

    # 5. Generate auditor-ready report
    if skip_report:
        log.info("Skipping OpenAI report generation (--skip-report)")
    else:
        log.info("=== Phase 4: Report Generation ===")
        try:
            generator = ReportGenerator()
            report_path = generator.generate_and_save(
                coverage_summary=coverage_summary,
                scoring_summary=scoring_summary,
                evidence_items=[e.to_dict() for e in evidence_items],
                output_dir=output_dir,
            )
            log.info("Audit report saved to %s", report_path)
        except Exception:
            log.exception("Failed to generate report")

    log.info("=== Pipeline Complete ===")
    return {
        "evidence_count": len(evidence_items),
        "coverage": coverage_summary,
        "scoring": scoring_summary,
    }


def main():
    parser = argparse.ArgumentParser(description="SOC 2 Evidence Tracer")
    parser.add_argument(
        "--skip-report",
        action="store_true",
        help="Skip OpenAI report generation",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for output files (default: reports)",
    )
    args = parser.parse_args()
    run_pipeline(skip_report=args.skip_report, output_dir=args.output_dir)


if __name__ == "__main__":
    main()
