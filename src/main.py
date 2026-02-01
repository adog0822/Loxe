import json
import os
from datetime import datetime
from dotenv import load_dotenv
from aws_connectors.iam_collector import IAMEvidenceCollector
from soc2_mapping.control_mapper import SOC2ControlMapper
from scoring.freshness_scorer import FreshnessScorer
from reporting.openai_reporter import OpenAIReporter

def main():
    """Main entry point for Evidence Tracer Agent"""
    print("🚀 Starting Evidence Tracer Agent - SOC 2 MVP")

    # Load environment variables
    load_dotenv()

    # Check required environment variables
    required_vars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'OPENAI_API_KEY']
    for var in required_vars:
        if not os.getenv(var):
            print(f"❌ Missing required environment variable: {var}")
            return

    # Initialize components
    print("1. Collecting evidence from AWS...")
    collector = IAMEvidenceCollector()
    evidence = collector.collect_user_evidence()

    print(f"   ✓ Collected evidence for {len(evidence['users'])} IAM users")

    # Map to SOC 2 controls
    print("\n2. Mapping evidence to SOC 2 controls...")
    for control_id in SOC2ControlMapper.CONTROLS.keys():
        print(f"   • {control_id}: {SOC2ControlMapper.CONTROLS[control_id]['name']}")

    # Calculate freshness score
    print("\n3. Calculating freshness & gap scores...")
    scorer = FreshnessScorer()
    scores = scorer.calculate_scores(evidence)

    print(f"   ✓ Freshness Score: {scores['freshness']['score']}/100")
    print(f"   ✓ Gap Detection: {scores['gap_detection']['missing_controls']} potential gaps")

    # Generate report
    print("\n4. Generating auditor-ready report...")
    reporter = OpenAIReporter()
    report = reporter.generate_report(evidence, scores)

    # Save outputs
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Save raw evidence
    with open(f"{output_dir}/evidence_{timestamp}.json", "w") as f:
        json.dump(evidence, f, indent=2)

    # Save scores
    with open(f"{output_dir}/scores_{timestamp}.json", "w") as f:
        json.dump(scores, f, indent=2)

    # Save report
    with open(f"{output_dir}/report_{timestamp}.md", "w") as f:
        f.write(report)

    print(f"\n✅ MVP Demo Complete!")
    print(f"📁 Outputs saved to: {output_dir}/")
    print(f"📄 Report: report_{timestamp}.md")
    print(f"📊 Scores: scores_{timestamp}.json")
    print(f"🔍 Evidence: evidence_{timestamp}.json")

if __name__ == "__main__":
    main()
