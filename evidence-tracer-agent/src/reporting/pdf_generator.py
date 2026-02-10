"""PDF report generator for SOC 2 evidence assessment reports."""

import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


_DARK = colors.HexColor("#1a1a2e")
_ZEBRA = colors.HexColor("#f5f5f5")
_RED = colors.HexColor("#e74c3c")
_ORANGE = colors.HexColor("#f39c12")
_BLUE = colors.HexColor("#3498db")
_GREEN = colors.HexColor("#27ae60")


def _build_styles() -> dict[str, ParagraphStyle]:
    """Create reusable paragraph styles for the report."""
    base = getSampleStyleSheet()
    custom: dict[str, ParagraphStyle] = {
        "title": base["Title"],
        "normal": base["Normal"],
    }
    custom["subtitle"] = ParagraphStyle(
        "Subtitle",
        parent=base["Normal"],
        fontSize=11,
        textColor=colors.grey,
        spaceAfter=20,
    )
    custom["section"] = ParagraphStyle(
        "SectionHeader",
        parent=base["Heading2"],
        spaceAfter=12,
        textColor=_DARK,
    )
    custom["finding"] = ParagraphStyle(
        "Finding",
        parent=base["Normal"],
        leftIndent=20,
        spaceAfter=6,
        fontSize=9,
    )
    return custom


def _header_table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), _DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _ZEBRA]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]
    )


def _coverage_label(pct: float) -> str:
    if pct >= 80:
        return "Good"
    if pct >= 50:
        return "Moderate"
    return "Needs Attention"


def _freshness_label(score: float) -> str:
    if score >= 80:
        return "Fresh"
    if score >= 50:
        return "Acceptable"
    return "Stale"


def _severity_color(severity: str) -> colors.Color:
    return {"HIGH": _RED, "MEDIUM": _ORANGE, "LOW": _BLUE}.get(severity, colors.grey)


class PDFReportGenerator:
    """Generates a downloadable PDF compliance report from scan results."""

    def generate(
        self,
        results: dict[str, Any],
        ai_analysis: dict[str, Any] | None = None,
        company_name: str = "Demo Company",
    ) -> bytes:
        """Build the full PDF and return it as raw bytes."""
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
        )
        styles = _build_styles()
        story: list[Any] = []

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # --- Title ---
        story.append(Paragraph("SOC 2 Evidence Assessment Report", styles["title"]))
        story.append(Paragraph(f"{company_name}  |  {now_str}", styles["subtitle"]))

        # --- Executive Summary ---
        story.append(Paragraph("Executive Summary", styles["section"]))

        scores = results.get("scores", {})
        coverage = results.get("coverage", {})
        cov_pct = coverage.get("coverage_pct", 0)
        fresh = scores.get("freshness_score", 0)
        risk = ai_analysis.get("risk_rating", "N/A") if ai_analysis else "N/A"

        summary_rows = [
            ["Metric", "Value", "Status"],
            [
                "Evidence Types Collected",
                str(len(results.get("evidence_types", []))),
                "",
            ],
            [
                "SOC 2 Controls Covered",
                f"{coverage.get('covered_count', 0)}/{coverage.get('total_controls', 0)}",
                _coverage_label(cov_pct),
            ],
            ["Coverage Percentage", f"{cov_pct}%", _coverage_label(cov_pct)],
            ["Freshness Score", f"{fresh}/100", _freshness_label(fresh)],
            ["Risk Rating", risk, ""],
        ]

        tbl = Table(summary_rows, colWidths=[200, 120, 120])
        tbl.setStyle(_header_table_style())
        story.append(tbl)
        story.append(Spacer(1, 20))

        # --- Control Coverage ---
        story.append(Paragraph("Control Coverage", styles["section"]))

        covered = coverage.get("covered", {})
        gaps = coverage.get("gaps", {})

        if covered:
            story.append(
                Paragraph("<b>Covered Controls</b>", styles["normal"])
            )
            for cid, ev_list in covered.items():
                story.append(
                    Paragraph(
                        f"<b>{cid}</b>: {', '.join(ev_list)}", styles["finding"]
                    )
                )
            story.append(Spacer(1, 10))

        if gaps:
            story.append(
                Paragraph("<b>Gap Controls (No Evidence)</b>", styles["normal"])
            )
            for cid, gap_info in gaps.items():
                story.append(
                    Paragraph(
                        f"<b>{cid} — {gap_info['name']}</b>: "
                        f"needs {', '.join(gap_info['missing_evidence'])}",
                        styles["finding"],
                    )
                )
            story.append(Spacer(1, 20))

        # --- AI Analysis ---
        if ai_analysis and ai_analysis.get("findings"):
            story.append(Paragraph("AI Policy Analysis", styles["section"]))
            story.append(
                Paragraph(ai_analysis.get("summary", ""), styles["normal"])
            )
            story.append(Spacer(1, 12))

            for finding in ai_analysis["findings"]:
                sev = finding.get("severity", "INFO")
                sc = _severity_color(sev)
                story.append(
                    Paragraph(
                        f'<font color="{sc.hexval()}">'
                        f"<b>[{sev}]</b></font> "
                        f"{finding['title']}  ({finding['control']})",
                        styles["normal"],
                    )
                )
                story.append(
                    Paragraph(finding["description"], styles["finding"])
                )
                story.append(
                    Paragraph(
                        f"<i>Recommendation: {finding['recommendation']}</i>",
                        styles["finding"],
                    )
                )
                story.append(Spacer(1, 8))

            story.append(Spacer(1, 12))

        # --- Freshness Details ---
        freshness_details = scores.get("freshness_details", {})
        if freshness_details:
            story.append(Paragraph("Evidence Freshness", styles["section"]))
            rows = [["Evidence Type", "Score", "Age (hours)", "Status"]]
            for etype, detail in freshness_details.items():
                rows.append(
                    [
                        etype,
                        f"{detail['score']}/100",
                        str(detail.get("age_hours", "N/A")),
                        detail.get("label", "unknown"),
                    ]
                )
            ftbl = Table(rows, colWidths=[180, 80, 80, 80])
            ftbl.setStyle(_header_table_style())
            story.append(ftbl)

        doc.build(story)
        return buf.getvalue()
