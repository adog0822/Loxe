#!/usr/bin/env python3
"""
SOC 2 Evidence Tracer Agent - Main Orchestrator

Runs the full evidence collection, control mapping, and freshness scoring
pipeline. Produces SOC 2 compliance reports in the data/ directory.
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Ensure src is on path
sys.path.insert(0, os.path.dirname(__file__))

from aws_connectors.iam_collector import IAMCollector
from soc2_mapping.control_mapper import SOC2ControlMapper
from scoring.freshness_scorer import FreshnessScorer

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


def print_banner():
    if HAS_RICH:
        console.print(Panel.fit(
            "[bold cyan]SOC 2 Evidence Tracer Agent[/bold cyan] v0.1.0\n"
            "[dim]Collect IAM evidence -> Map to SOC 2 controls -> Score freshness[/dim]",
            border_style="cyan",
        ))
    else:
        print("=" * 60)
        print("  SOC 2 Evidence Tracer Agent v0.1.0")
        print("  Collect IAM evidence -> Map to SOC 2 controls -> Score freshness")
        print("=" * 60)
        print()


def print_step(step: int, msg: str):
    if HAS_RICH:
        console.print(f"\n[bold yellow]Step {step}:[/bold yellow] {msg}")
    else:
        print(f"\nStep {step}: {msg}")


def print_info(msg: str):
    if HAS_RICH:
        console.print(f"  [dim]{msg}[/dim]")
    else:
        print(f"  {msg}")


def print_soc2_summary(report):
    """Print the SOC 2 control mapping summary."""
    if HAS_RICH:
        table = Table(title="SOC 2 Control Assessment", show_header=True)
        table.add_column("Control", style="bold", width=10)
        table.add_column("Name", width=40)
        table.add_column("Status", justify="center", width=10)
        table.add_column("Checks", justify="center", width=8)

        for ctrl in report.controls:
            status_style = {
                "PASS": "[green]PASS[/green]",
                "FAIL": "[red]FAIL[/red]",
                "WARNING": "[yellow]WARN[/yellow]",
            }.get(ctrl.status, ctrl.status)

            check_summary = f"{sum(1 for c in ctrl.checks if c.status == 'PASS')}/{len(ctrl.checks)}"
            table.add_row(ctrl.control_id, ctrl.control_name, status_style, check_summary)

        console.print(table)

        # Summary bar
        console.print(f"\n  [green]Passing: {report.passing}[/green] | "
                      f"[red]Failing: {report.failing}[/red] | "
                      f"[yellow]Warnings: {report.warnings}[/yellow] | "
                      f"Total: {report.total_controls}")
    else:
        print("\n  SOC 2 Control Assessment")
        print(f"  {'Control':<10} {'Name':<40} {'Status':<10} {'Checks':<8}")
        print(f"  {'-'*10} {'-'*40} {'-'*10} {'-'*8}")
        for ctrl in report.controls:
            check_summary = f"{sum(1 for c in ctrl.checks if c.status == 'PASS')}/{len(ctrl.checks)}"
            print(f"  {ctrl.control_id:<10} {ctrl.control_name:<40} {ctrl.status:<10} {check_summary:<8}")
        print(f"\n  Passing: {report.passing} | Failing: {report.failing} | Warnings: {report.warnings}")


def print_freshness_summary(report):
    """Print the freshness scoring summary."""
    if HAS_RICH:
        table = Table(title="Evidence Freshness Scores", show_header=True)
        table.add_column("Metric", style="bold", width=25)
        table.add_column("Score", justify="center", width=10)
        table.add_column("Grade", justify="center", width=8)
        table.add_column("Details", width=50)

        for m in report.metrics:
            grade_style = {
                "A": "[green]A[/green]",
                "B": "[green]B[/green]",
                "C": "[yellow]C[/yellow]",
                "D": "[red]D[/red]",
                "F": "[red]F[/red]",
            }.get(m.grade, m.grade)

            table.add_row(m.metric_name, f"{m.value:.0%}", grade_style, m.details)

        console.print(table)

        # Overall
        overall_style = "green" if report.overall_score >= 80 else "yellow" if report.overall_score >= 60 else "red"
        console.print(f"\n  Overall Score: [{overall_style}]{report.overall_score}/100 ({report.overall_grade})[/{overall_style}]")
    else:
        print("\n  Evidence Freshness Scores")
        print(f"  {'Metric':<25} {'Score':<10} {'Grade':<8} {'Details'}")
        print(f"  {'-'*25} {'-'*10} {'-'*8} {'-'*40}")
        for m in report.metrics:
            print(f"  {m.metric_name:<25} {m.value:.0%}{'':>5} {m.grade:<8} {m.details}")
        print(f"\n  Overall Score: {report.overall_score}/100 ({report.overall_grade})")


def print_gaps_summary(gaps):
    """Print detected compliance gaps."""
    if not gaps:
        if HAS_RICH:
            console.print("\n  [green]No compliance gaps detected![/green]")
        else:
            print("\n  No compliance gaps detected!")
        return

    if HAS_RICH:
        table = Table(title="Compliance Gaps Detected", show_header=True)
        table.add_column("ID", width=10)
        table.add_column("Severity", justify="center", width=10)
        table.add_column("Category", width=22)
        table.add_column("Description", width=50)
        table.add_column("Users", width=20)

        for g in gaps:
            sev_style = {
                "CRITICAL": "[bold red]CRIT[/bold red]",
                "HIGH": "[red]HIGH[/red]",
                "MEDIUM": "[yellow]MED[/yellow]",
                "LOW": "[dim]LOW[/dim]",
            }.get(g.severity, g.severity)

            users_str = ", ".join(g.affected_users[:3])
            if len(g.affected_users) > 3:
                users_str += f" +{len(g.affected_users) - 3}"

            table.add_row(g.gap_id, sev_style, g.category, g.description, users_str)

        console.print(table)
    else:
        print("\n  Compliance Gaps Detected")
        for g in gaps:
            users_str = ", ".join(g.affected_users[:3])
            print(f"  [{g.severity}] {g.gap_id}: {g.description}")
            print(f"           Users: {users_str}")


def main():
    print_banner()

    data_dir = Path(__file__).parent.parent / "data"
    data_dir.mkdir(exist_ok=True)

    demo_mode = os.getenv("DEMO_MODE", "false").lower() == "true"
    mode_label = "DEMO MODE" if demo_mode else "LIVE MODE"
    if HAS_RICH:
        console.print(f"  Mode: [bold]{'[yellow]' + mode_label + '[/yellow]' if demo_mode else mode_label}[/bold]")
    else:
        print(f"  Mode: {mode_label}")

    # ── Step 1: Collect IAM Evidence ─────────────────────────────────
    print_step(1, "Collecting IAM evidence...")

    collector = IAMCollector()
    iam_export_path = str(data_dir / "iam_evidence.json")
    users = collector.collect_and_export(iam_export_path)

    summary = collector.get_summary(users)
    print_info(f"Collected {summary['total_users']} IAM users")
    print_info(f"MFA coverage: {summary['mfa_coverage_pct']}%")
    print_info(f"Stale access keys: {summary['stale_access_keys']}")
    print_info(f"Admin users: {summary['admin_users']}")
    print_info(f"Exported to: {iam_export_path}")

    # ── Step 2: Map to SOC 2 Controls ────────────────────────────────
    print_step(2, "Mapping evidence to SOC 2 controls...")

    mapper = SOC2ControlMapper(account_id=collector.account_id)
    soc2_report = mapper.evaluate(users)

    soc2_export_path = str(data_dir / "soc2_report.json")
    mapper.export_report(soc2_report, soc2_export_path)
    print_info(f"Evaluated {soc2_report.total_controls} controls")
    print_info(f"Exported to: {soc2_export_path}")

    print_soc2_summary(soc2_report)

    # ── Step 3: Score Freshness & Detect Gaps ────────────────────────
    print_step(3, "Scoring evidence freshness and detecting gaps...")

    scorer = FreshnessScorer()
    freshness_report = scorer.score(users)

    freshness_export_path = str(data_dir / "freshness_report.json")
    scorer.export_report(freshness_report, freshness_export_path)
    print_info(f"Exported to: {freshness_export_path}")

    print_freshness_summary(freshness_report)

    # ── Step 4: Print Gaps ───────────────────────────────────────────
    print_step(4, "Compliance gap summary...")
    print_gaps_summary(freshness_report.gaps)

    # ── Final Summary ────────────────────────────────────────────────
    if HAS_RICH:
        console.print(Panel.fit(
            f"[bold]SOC 2 Evidence Tracing Complete[/bold]\n\n"
            f"Controls: [green]{soc2_report.passing} pass[/green] / "
            f"[red]{soc2_report.failing} fail[/red] / "
            f"[yellow]{soc2_report.warnings} warn[/yellow]\n"
            f"Freshness: {freshness_report.overall_score}/100 ({freshness_report.overall_grade})\n"
            f"Gaps: [red]{freshness_report.critical_gaps} critical[/red], "
            f"[yellow]{freshness_report.high_gaps} high[/yellow]\n\n"
            f"Reports saved to: {data_dir}/",
            title="Results",
            border_style="green" if soc2_report.failing == 0 else "red",
        ))
    else:
        print(f"\n{'=' * 60}")
        print(f"  SOC 2 Evidence Tracing Complete")
        print(f"  Controls: {soc2_report.passing} pass / {soc2_report.failing} fail / {soc2_report.warnings} warn")
        print(f"  Freshness: {freshness_report.overall_score}/100 ({freshness_report.overall_grade})")
        print(f"  Gaps: {freshness_report.critical_gaps} critical, {freshness_report.high_gaps} high")
        print(f"  Reports saved to: {data_dir}/")
        print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
