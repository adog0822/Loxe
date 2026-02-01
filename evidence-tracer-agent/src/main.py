"""Evidence Tracer Agent - Main entry point."""

import os
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass


def check_demo_mode() -> bool:
    """Check if the agent is running in demo mode.

    Returns:
        True if DEMO_MODE is enabled, False otherwise.
    """
    return os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")


def validate_credentials() -> bool:
    """Validate that required credentials are set.

    Returns:
        True if all required credentials are present.

    Raises:
        SystemExit: If required credentials are missing.
    """
    missing = []

    if not os.getenv("AWS_ACCESS_KEY_ID"):
        missing.append("AWS_ACCESS_KEY_ID")
    if not os.getenv("AWS_SECRET_ACCESS_KEY"):
        missing.append("AWS_SECRET_ACCESS_KEY")
    if not os.getenv("OPENAI_API_KEY"):
        missing.append("OPENAI_API_KEY")

    if missing:
        print("\n[ERROR] Missing required credentials:")
        for cred in missing:
            print(f"  - {cred}")
        print("\nSet these in your .env file or environment variables.")
        print("Alternatively, set DEMO_MODE=true to run without credentials.")
        sys.exit(1)

    return True


def run_demo() -> None:
    """Run the Evidence Tracer Agent in demo mode."""
    from src.reporting.openai_reporter import OpenAIReporter

    print("=" * 60)
    print("  EVIDENCE TRACER AGENT - DEMO MODE")
    print("=" * 60)
    print()
    print(f"  Started:    {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Mode:       DEMO (simulated data)")
    print(f"  Output:     evidence-tracer-agent/data/")
    print()
    print("-" * 60)

    # Phase 1: Initialize
    print("\n[1/4] Initializing Evidence Tracer Agent...")
    print("  [DEMO] Skipping AWS credential validation")
    print("  [DEMO] Skipping OpenAI credential validation")
    print("  [OK]   Agent initialized successfully")

    # Phase 2: Collect evidence
    print("\n[2/4] Collecting evidence from AWS environment...")
    print("  [DEMO] Simulating CloudTrail evidence collection  ... 2,847 events")
    print("  [DEMO] Simulating AWS Config rules evaluation     ...   156 rules")
    print("  [DEMO] Simulating IAM policy analysis             ...    43 policies")
    print("  [DEMO] Simulating GuardDuty findings review       ...    12 findings")
    print("  [DEMO] Simulating Security Hub aggregation        ...    89 findings")
    print("  [DEMO] Simulating S3 bucket configuration audit   ...    34 buckets")
    print("  [DEMO] Simulating RDS instance security review    ...     8 instances")
    print("  [DEMO] Simulating KMS key policy analysis         ...    15 keys")
    print("  [OK]   Evidence collection complete: 3,204 items")

    # Phase 3: Generate report
    print("\n[3/4] Generating SOC 2 compliance report...")
    print("  [DEMO] Using built-in report generator (no OpenAI API call)")

    reporter = OpenAIReporter()
    report = reporter.generate_report()

    data_dir = str(PROJECT_ROOT / "data")
    report_path = reporter.save_report(report, output_dir=data_dir)
    metadata_path = reporter.save_report_json(output_dir=data_dir)

    print("  [OK]   Report generated successfully")

    # Phase 4: Summary
    print("\n[4/4] Finalizing...")
    print("  [OK]   All phases complete")

    # Demo summary
    print("\n" + "=" * 60)
    print("  DEMO SUMMARY")
    print("=" * 60)
    print()
    print("  What was simulated:")
    print("  -------------------")
    print("  - AWS evidence collection (CloudTrail, Config, IAM,")
    print("    GuardDuty, Security Hub, S3, RDS, KMS)")
    print("  - SOC 2 control mapping and scoring")
    print("  - OpenAI-powered report generation")
    print()
    print("  Results:")
    print("  --------")
    print(f"  - Overall Compliance Score:  78/100")
    print(f"  - Controls Assessed:         8")
    print(f"  - Controls Compliant:        5")
    print(f"  - Controls Need Remediation: 2")
    print(f"  - Critical Gaps:             1")
    print(f"  - Total Findings:            5")
    print()
    print("  Output Files:")
    print("  -------------")
    print(f"  - Report:   {report_path}")
    print(f"  - Metadata: {metadata_path}")
    print()
    print("  To run in production mode:")
    print("  --------------------------")
    print("  1. Set DEMO_MODE=false in .env")
    print("  2. Configure AWS credentials (AWS_ACCESS_KEY_ID, etc.)")
    print("  3. Set OPENAI_API_KEY for GPT-4 report generation")
    print("  4. Run: python src/main.py")
    print()
    print("=" * 60)
    print(f"  Completed: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 60)


def run_production() -> None:
    """Run the Evidence Tracer Agent in production mode."""
    print("=" * 60)
    print("  EVIDENCE TRACER AGENT - PRODUCTION MODE")
    print("=" * 60)
    print()
    print(f"  Started: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Mode:    PRODUCTION (live AWS data)")
    print()
    print("-" * 60)

    # Phase 1: Initialize
    print("\n[1/4] Initializing Evidence Tracer Agent...")
    validate_credentials()
    print("  [OK] Credentials validated")

    # Phase 2: Collect evidence
    print("\n[2/4] Collecting evidence from AWS environment...")
    # TODO: Implement AWS evidence collection
    print("  [WARN] AWS evidence collectors not yet implemented")
    print("  [WARN] Using placeholder evidence data")

    evidence = {
        "cloudtrail": {"status": "placeholder"},
        "config": {"status": "placeholder"},
        "iam": {"status": "placeholder"},
    }

    # Phase 3: Generate report
    print("\n[3/4] Generating SOC 2 compliance report...")
    from src.reporting.openai_reporter import OpenAIReporter

    reporter = OpenAIReporter()
    report = reporter.generate_report(evidence=evidence)

    data_dir = str(PROJECT_ROOT / "data")
    report_path = reporter.save_report(report, output_dir=data_dir)
    metadata_path = reporter.save_report_json(output_dir=data_dir)
    print("  [OK] Report generated successfully")

    # Phase 4: Summary
    print("\n[4/4] Finalizing...")
    print("  [OK] All phases complete")
    print()
    print(f"  Output Files:")
    print(f"  - Report:   {report_path}")
    print(f"  - Metadata: {metadata_path}")
    print()
    print("=" * 60)
    print(f"  Completed: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 60)


def main() -> None:
    """Run the Evidence Tracer Agent."""
    demo_mode = check_demo_mode()

    if demo_mode:
        print()
        print("[INFO] DEMO_MODE is enabled - running with simulated data")
        print()
        run_demo()
    else:
        print()
        print("[INFO] Running in PRODUCTION mode")
        print()
        run_production()


if __name__ == "__main__":
    main()
