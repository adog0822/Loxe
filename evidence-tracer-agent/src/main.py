"""Evidence Tracer Agent - Main CLI entry point."""

import json
import os

from src.ai_analysis.policy_analyzer import analyze_policies
from src.aws_connectors.iam_collector import collect
from src.scoring.freshness_scorer import FreshnessScorer
from src.soc2_mapping.control_mapper import SOC2ControlMapper


def main() -> None:
    """Run the Evidence Tracer Agent."""
    print("=" * 60)
    print("  Evidence Tracer Agent - SOC 2 Compliance Scanner")
    print("=" * 60)
    print()

    demo_mode = os.environ.get("DEMO_MODE", "true").lower() in ("true", "1", "yes")
    if demo_mode:
        print("[Mode] DEMO_MODE enabled - using synthetic AWS evidence")
    print()

    # Step 1: Collect IAM evidence
    print("[1/4] Collecting IAM evidence...")
    evidence = collect()
    evidence_types = sorted(evidence.keys())
    print(f"      Collected {len(evidence_types)} evidence types: {', '.join(evidence_types)}")
    print()

    # Step 2: Map evidence to SOC 2 controls
    print("[2/4] Mapping evidence to SOC 2 controls...")
    mapper = SOC2ControlMapper()
    coverage = mapper.get_coverage_summary(evidence)

    print(f"      Controls covered: {coverage['covered_count']}/{coverage['total_controls']}"
          f" ({coverage['coverage_pct']}%)")
    print()

    if coverage["covered"]:
        print("      Covered controls:")
        for cid, evidence_list in coverage["covered"].items():
            ctrl = mapper.get_control(cid)
            print(f"        [{cid}] {ctrl['name']}: {', '.join(evidence_list)}")

    if coverage["gaps"]:
        print()
        print("      Gap controls (no evidence found):")
        for cid, gap_info in coverage["gaps"].items():
            print(f"        [{cid}] {gap_info['name']}: needs {', '.join(gap_info['missing_evidence'])}")
    print()

    # Step 3: AI-powered policy analysis
    print("[3/4] Running AI policy analysis...")
    ai_analysis = analyze_policies(evidence)

    print(f"      Risk Rating: {ai_analysis.get('risk_rating', 'N/A')}")
    print(f"      Findings:    {len(ai_analysis.get('findings', []))}")
    for finding in ai_analysis.get("findings", []):
        print(f"        [{finding['severity']}] {finding['title']} ({finding['control']})")
    print()

    # Step 4: Score freshness and gaps
    print("[4/4] Scoring evidence freshness...")
    scorer = FreshnessScorer()
    scores = scorer.calculate_scores(evidence)

    print(f"      Freshness Score: {scores['freshness_score']}/100")
    print(f"      Gap Score:       {scores['gap_score']}/100")
    print()
    print("      Per-evidence freshness:")
    for etype, detail in scores["freshness_details"].items():
        age_str = f"{detail['age_hours']}h" if detail["age_hours"] is not None else "n/a"
        print(f"        {etype}: {detail['score']}/100 ({detail['label']}, age={age_str})")

    # Final report summary
    print()
    print("=" * 60)
    print("  REPORT SUMMARY")
    print("=" * 60)
    print(f"  Evidence types collected:  {len(evidence_types)}")
    print(f"  SOC 2 controls covered:    {coverage['covered_count']}/{coverage['total_controls']}")
    print(f"  Coverage percentage:        {coverage['coverage_pct']}%")
    print(f"  Freshness score:            {scores['freshness_score']}/100")
    print(f"  Gap score:                  {scores['gap_score']}/100")
    print(f"  AI risk rating:             {ai_analysis.get('risk_rating', 'N/A')}")
    print(f"  AI findings:                {len(ai_analysis.get('findings', []))}")
    print("=" * 60)
    print()

    # Write JSON report to data/
    report = {
        "evidence_types": evidence_types,
        "coverage": coverage,
        "scores": {
            "freshness_score": scores["freshness_score"],
            "gap_score": scores["gap_score"],
            "freshness_details": scores["freshness_details"],
        },
        "ai_analysis": ai_analysis,
    }
    report_path = os.path.join(os.path.dirname(__file__), "..", "data", "report.json")
    report_path = os.path.normpath(report_path)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"  JSON report written to: {report_path}")
    print()


if __name__ == "__main__":
    main()
