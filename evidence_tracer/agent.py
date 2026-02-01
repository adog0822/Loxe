"""
Evidence Tracer Agent
Main orchestrator that ties together claim extraction, evidence search,
scoring, and report generation into a complete tracing pipeline.
"""

import logging
import time
from pathlib import Path

from .config import Config
from .models import TraceReport, ClaimVerification
from .extractor import extract_claims
from .searcher import search_evidence
from .scorer import verify_claim
from .reporter import save_report, generate_markdown

logger = logging.getLogger(__name__)


class EvidenceTracerAgent:
    """
    The core Evidence Tracer Agent.

    Pipeline:
    1. Accept document text
    2. Extract verifiable claims
    3. Search for evidence per claim
    4. Score and verify each claim
    5. Generate a comprehensive report
    """

    def __init__(self, config: Config = None, progress_callback=None):
        self.config = config or Config()
        self.progress_callback = progress_callback

    def _report_progress(self, message: str):
        """Report progress to callback or logger."""
        logger.info(message)
        if self.progress_callback:
            self.progress_callback(message)

    def trace(
        self,
        text: str,
        document_name: str = "document",
        max_results_per_claim: int = None,
        search_timeout: int = None,
    ) -> TraceReport:
        """
        Run the full evidence tracing pipeline on a document.

        Args:
            text: The full text of the document to analyze.
            document_name: Name of the document (for the report).
            max_results_per_claim: Override max search results per claim.
            search_timeout: Override search timeout.

        Returns:
            A TraceReport with all findings.
        """
        max_results = max_results_per_claim or self.config.max_search_results
        timeout = search_timeout or self.config.search_timeout

        # Step 1: Extract claims
        self._report_progress("Extracting claims from document...")
        claims = extract_claims(text)
        self._report_progress(f"Found {len(claims)} verifiable claim(s)")

        if not claims:
            self._report_progress("No verifiable claims found in the document.")
            return TraceReport(
                document_name=document_name,
                total_claims=0,
                summary="No verifiable claims were found in this document.",
            )

        # Step 2 & 3: Search and score evidence for each claim
        verifications: list[ClaimVerification] = []

        for i, claim in enumerate(claims):
            self._report_progress(
                f"Tracing claim {i + 1}/{len(claims)}: {claim.text[:60]}..."
            )

            # Search for evidence
            sources = search_evidence(
                claim,
                max_results=max_results,
                timeout=timeout,
            )
            self._report_progress(
                f"  Found {len(sources)} source(s) for claim #{claim.id}"
            )

            # Score and verify
            verification = verify_claim(claim, sources)
            verifications.append(verification)

            self._report_progress(
                f"  Verdict: {verification.verdict} "
                f"(confidence: {verification.overall_score:.1%})"
            )

            # Brief pause to be respectful to search APIs
            if i < len(claims) - 1:
                time.sleep(0.5)

        # Step 4: Compile report
        self._report_progress("Compiling evidence trace report...")

        report = TraceReport(
            document_name=document_name,
            total_claims=len(claims),
            verifications=verifications,
        )

        # Generate summary
        report.summary = self._generate_summary(report)
        self._report_progress("Evidence tracing complete.")

        return report

    def trace_file(
        self,
        filepath: str | Path,
        max_results_per_claim: int = None,
    ) -> TraceReport:
        """
        Trace evidence for claims in a file.

        Args:
            filepath: Path to the text file to analyze.
            max_results_per_claim: Override max search results per claim.

        Returns:
            A TraceReport with all findings.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        text = path.read_text(encoding='utf-8')
        document_name = path.name

        return self.trace(
            text=text,
            document_name=document_name,
            max_results_per_claim=max_results_per_claim,
        )

    def trace_and_save(
        self,
        text: str,
        document_name: str = "document",
        output_format: str = None,
        max_results_per_claim: int = None,
    ) -> tuple[TraceReport, Path]:
        """
        Run tracing and save the report.

        Returns:
            Tuple of (TraceReport, path to saved report).
        """
        fmt = output_format or self.config.default_format

        report = self.trace(
            text=text,
            document_name=document_name,
            max_results_per_claim=max_results_per_claim,
        )

        filepath = save_report(report, fmt=fmt, config=self.config)
        self._report_progress(f"Report saved to: {filepath}")

        return report, filepath

    def _generate_summary(self, report: TraceReport) -> str:
        """Generate a human-readable summary of the report."""
        total = report.total_claims
        verified = report.verified_count
        avg_conf = report.avg_confidence

        parts = [
            f"Analyzed {total} claim(s) from '{report.document_name}'.",
            f"{verified} claim(s) had evidence found ({verified/total:.0%} coverage)." if total > 0 else "",
            f"Average confidence score: {avg_conf:.1%}." if avg_conf > 0 else "",
        ]

        # Highlight concerns
        from .models import EvidenceStrength
        disputed = [
            v for v in report.verifications
            if v.overall_strength == EvidenceStrength.CONTRADICTORY
        ]
        if disputed:
            parts.append(
                f"WARNING: {len(disputed)} claim(s) have contradicting evidence "
                f"and should be reviewed."
            )

        unverified = [
            v for v in report.verifications
            if v.overall_strength == EvidenceStrength.NONE_FOUND
        ]
        if unverified:
            parts.append(
                f"NOTE: {len(unverified)} claim(s) could not be verified "
                f"(no relevant evidence found)."
            )

        return ' '.join(p for p in parts if p)
