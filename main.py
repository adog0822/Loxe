#!/usr/bin/env python3
"""
Evidence Tracer Agent - CLI Entry Point

Usage:
    python main.py trace <file>              Trace claims in a file
    python main.py trace --text "..."        Trace claims from text input
    python main.py trace <file> --format json Output as JSON
    python main.py demo                      Run with sample data
"""

import sys
import logging
from pathlib import Path

try:
    import click
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.markdown import Markdown
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from evidence_tracer.agent import EvidenceTracerAgent
from evidence_tracer.config import Config
from evidence_tracer.reporter import generate_markdown, generate_json, save_report
from evidence_tracer.models import EvidenceStrength


# ── Rich console output helpers ──────────────────────────────────────────

if HAS_RICH:
    console = Console()

    def print_header():
        console.print(Panel.fit(
            "[bold blue]Evidence Tracer Agent[/bold blue] v0.1.0\n"
            "[dim]Trace, verify, and score claims against real-world evidence[/dim]",
            border_style="blue",
        ))

    def print_report_summary(report):
        table = Table(title="Evidence Trace Summary", show_header=True)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Document", report.document_name)
        table.add_row("Total Claims", str(report.total_claims))
        table.add_row("Verified", f"{report.verified_count}/{report.total_claims}")
        table.add_row("Avg Confidence", f"{report.avg_confidence:.1%}")

        console.print(table)
        console.print()

        # Verdict breakdown
        vtable = Table(title="Verdict Breakdown", show_header=True)
        vtable.add_column("Category", style="bold")
        vtable.add_column("Count", justify="right")
        vtable.add_column("Claims")

        strength_styles = {
            EvidenceStrength.STRONG: ("green", "Well-Supported"),
            EvidenceStrength.MODERATE: ("yellow", "Partially Supported"),
            EvidenceStrength.WEAK: ("dark_orange", "Weakly Supported"),
            EvidenceStrength.CONTRADICTORY: ("red", "Disputed"),
            EvidenceStrength.NONE_FOUND: ("dim", "Unverified"),
        }

        for strength, (style, label) in strength_styles.items():
            matching = [v for v in report.verifications if v.overall_strength == strength]
            if matching:
                claim_ids = ", ".join(f"#{v.claim.id}" for v in matching)
                vtable.add_row(f"[{style}]{label}[/{style}]", str(len(matching)), claim_ids)

        console.print(vtable)
        console.print()

        # Print each claim detail
        for v in report.verifications:
            strength_style = {
                EvidenceStrength.STRONG: "green",
                EvidenceStrength.MODERATE: "yellow",
                EvidenceStrength.WEAK: "dark_orange",
                EvidenceStrength.CONTRADICTORY: "red",
                EvidenceStrength.NONE_FOUND: "dim",
            }.get(v.overall_strength, "white")

            console.print(f"\n[bold]Claim #{v.claim.id}[/bold] [{strength_style}][{v.overall_strength.value.upper()}][/{strength_style}]")
            console.print(f"  [italic]\"{v.claim.text}\"[/italic]")
            console.print(f"  Type: {v.claim.claim_type.value} | Confidence: {v.overall_score:.1%}")
            console.print(f"  Verdict: {v.verdict}")

            if v.evidence_list:
                for e in v.evidence_list[:3]:  # Show top 3
                    stance_color = "green" if e.supports_claim else "red"
                    stance = "Supports" if e.supports_claim else "Contradicts"
                    console.print(f"    [{stance_color}]{stance}[/{stance_color}] ({e.confidence_score:.0%}) - {e.source.title[:60]}")
            else:
                console.print(f"    [dim]No evidence found[/dim]")

        if report.summary:
            console.print(f"\n[bold]Summary:[/bold] {report.summary}")

else:
    # Fallback: plain text output
    def print_header():
        print("=" * 60)
        print("  Evidence Tracer Agent v0.1.0")
        print("  Trace, verify, and score claims against real-world evidence")
        print("=" * 60)
        print()

    def print_report_summary(report):
        print(f"\n{'=' * 60}")
        print(f"EVIDENCE TRACE SUMMARY")
        print(f"{'=' * 60}")
        print(f"Document:       {report.document_name}")
        print(f"Total Claims:   {report.total_claims}")
        print(f"Verified:       {report.verified_count}/{report.total_claims}")
        print(f"Avg Confidence: {report.avg_confidence:.1%}")
        print()

        for v in report.verifications:
            print(f"\nClaim #{v.claim.id} [{v.overall_strength.value.upper()}]")
            print(f"  \"{v.claim.text}\"")
            print(f"  Verdict: {v.verdict} | Confidence: {v.overall_score:.1%}")
            for e in v.evidence_list[:3]:
                stance = "+" if e.supports_claim else "-"
                print(f"    [{stance}] ({e.confidence_score:.0%}) {e.source.title[:60]}")

        if report.summary:
            print(f"\nSummary: {report.summary}")


# ── CLI Commands ─────────────────────────────────────────────────────────

@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def cli(verbose):
    """Evidence Tracer Agent - Verify claims with real-world evidence."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    )


@cli.command()
@click.argument('file', required=False, type=click.Path())
@click.option('--text', '-t', help='Trace claims from text string instead of file')
@click.option('--format', '-f', 'fmt', default='markdown',
              type=click.Choice(['markdown', 'json', 'html']),
              help='Output report format')
@click.option('--max-results', '-n', default=5,
              help='Max search results per claim')
@click.option('--save/--no-save', default=True,
              help='Save report to output directory')
@click.option('--quiet', '-q', is_flag=True, help='Only output the report, no progress')
def trace(file, text, fmt, max_results, save, quiet):
    """Trace and verify claims in a document or text."""
    print_header()

    config = Config()

    if not text and not file:
        click.echo("Error: Provide a FILE path or use --text to pass text directly.")
        click.echo("  Example: python main.py trace samples/pitch_deck_sample.txt")
        click.echo("  Example: python main.py trace --text 'The global AI market is worth $150 billion'")
        sys.exit(1)

    # Read input
    if file:
        path = Path(file)
        if not path.exists():
            click.echo(f"Error: File not found: {file}")
            sys.exit(1)
        doc_text = path.read_text(encoding='utf-8')
        doc_name = path.name
    else:
        doc_text = text
        doc_name = "text_input"

    # Progress callback
    def on_progress(msg):
        if not quiet:
            if HAS_RICH:
                console.print(f"  [dim]{msg}[/dim]")
            else:
                print(f"  {msg}")

    # Run the agent
    agent = EvidenceTracerAgent(config=config, progress_callback=on_progress)

    try:
        report = agent.trace(
            text=doc_text,
            document_name=doc_name,
            max_results_per_claim=max_results,
        )
    except KeyboardInterrupt:
        click.echo("\nTracing interrupted.")
        sys.exit(1)
    except Exception as e:
        click.echo(f"\nError during tracing: {e}")
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # Display results
    print_report_summary(report)

    # Save report
    if save:
        filepath = save_report(report, fmt=fmt, config=config)
        if HAS_RICH:
            console.print(f"\n[bold green]Report saved:[/bold green] {filepath}")
        else:
            print(f"\nReport saved: {filepath}")


@cli.command()
@click.option('--format', '-f', 'fmt', default='markdown',
              type=click.Choice(['markdown', 'json', 'html']),
              help='Output report format')
def demo(fmt):
    """Run Evidence Tracer with built-in sample data."""
    print_header()

    sample_path = Path(__file__).parent / "samples" / "pitch_deck_sample.txt"
    if not sample_path.exists():
        click.echo(f"Error: Sample file not found at {sample_path}")
        click.echo("Make sure the samples/ directory exists with sample data.")
        sys.exit(1)

    doc_text = sample_path.read_text(encoding='utf-8')
    config = Config()

    def on_progress(msg):
        if HAS_RICH:
            console.print(f"  [dim]{msg}[/dim]")
        else:
            print(f"  {msg}")

    if HAS_RICH:
        console.print("[bold]Running demo with sample pitch deck...[/bold]\n")
    else:
        print("Running demo with sample pitch deck...\n")

    agent = EvidenceTracerAgent(config=config, progress_callback=on_progress)

    try:
        report = agent.trace(
            text=doc_text,
            document_name="pitch_deck_sample.txt",
        )
    except Exception as e:
        click.echo(f"\nError during demo: {e}")
        sys.exit(1)

    print_report_summary(report)

    filepath = save_report(report, fmt=fmt, config=config)
    if HAS_RICH:
        console.print(f"\n[bold green]Demo report saved:[/bold green] {filepath}")
    else:
        print(f"\nDemo report saved: {filepath}")


@cli.command()
def version():
    """Show version information."""
    from evidence_tracer import __version__
    click.echo(f"Evidence Tracer Agent v{__version__}")


if __name__ == '__main__':
    cli()
