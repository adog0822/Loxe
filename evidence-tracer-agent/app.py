"""Streamlit dashboard for the Evidence Tracer Agent."""

import os
import sys

# Ensure the project root is on the path so ``from src...`` imports work
# when Streamlit is launched from the project directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st

from src.ai_analysis.policy_analyzer import analyze_policies
from src.auth.auth0_handler import Auth0Handler
from src.aws_connectors.iam_collector import collect
from src.aws_connectors.sts_connector import create_session
from src.reporting.pdf_generator import PDFReportGenerator
from src.scoring.freshness_scorer import FreshnessScorer
from src.soc2_mapping.control_mapper import SOC2ControlMapper


# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Evidence Tracer Agent",
    page_icon="\U0001f6e1\ufe0f",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

auth = Auth0Handler()
demo_mode = os.environ.get("DEMO_MODE", "").lower() in ("true", "1", "yes")

if not demo_mode and auth.is_configured:
    user = auth.check_auth()
    if user is None:
        st.title("Evidence Tracer Agent")
        st.markdown("### SOC 2 Compliance Scanner")
        st.divider()
        st.markdown("Please log in to continue.")
        st.link_button("Log in with Auth0", auth.get_login_url(), type="primary")
        st.stop()
else:
    user = None

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.title("Evidence Tracer")

    if demo_mode:
        st.info("DEMO MODE -- synthetic data, no credentials required")
    elif user:
        st.success(f"Logged in as **{user.get('name', user.get('email', 'User'))}**")
        if st.button("Logout"):
            auth.logout()
            st.rerun()

    st.divider()

    role_arn = ""
    region = "us-east-1"

    if not demo_mode:
        role_arn = st.text_input(
            "AWS Role ARN",
            placeholder="arn:aws:iam::123456789012:role/EvidenceTracerReadOnly",
        )
        region = st.selectbox(
            "Region",
            ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1"],
        )

    run_scan = st.button("Run Scan", type="primary", use_container_width=True)

    st.divider()
    st.caption("Evidence Tracer Agent v0.2.0")

# ---------------------------------------------------------------------------
# Run scan
# ---------------------------------------------------------------------------

if run_scan:
    if not demo_mode and not role_arn:
        st.warning("Enter an AWS Role ARN or enable DEMO_MODE.")
        st.stop()

    with st.status("Running compliance scan\u2026", expanded=True) as status:
        # 1 -- Collect
        st.write("Collecting IAM evidence\u2026")
        if demo_mode:
            os.environ["DEMO_MODE"] = "true"
            evidence = collect()
        else:
            session = create_session(role_arn, region)
            evidence = collect(session=session)

        # 2 -- Map
        st.write("Mapping to SOC 2 controls\u2026")
        mapper = SOC2ControlMapper()
        coverage = mapper.get_coverage_summary(evidence)

        # 3 -- Score
        st.write("Scoring evidence freshness\u2026")
        scorer = FreshnessScorer()
        scores = scorer.calculate_scores(evidence)

        # 4 -- AI Analysis
        st.write("Running AI policy analysis\u2026")
        ai_analysis = analyze_policies(evidence)

        status.update(label="Scan complete", state="complete")

    st.session_state["results"] = {
        "evidence_types": sorted(evidence.keys()),
        "coverage": coverage,
        "scores": {
            "freshness_score": scores["freshness_score"],
            "gap_score": scores["gap_score"],
            "freshness_details": scores["freshness_details"],
        },
    }
    st.session_state["ai_analysis"] = ai_analysis
    st.session_state["evidence"] = evidence

# ---------------------------------------------------------------------------
# Dashboard (shown after a scan completes)
# ---------------------------------------------------------------------------

if "results" not in st.session_state:
    st.title("Evidence Tracer Agent")
    st.markdown("### SOC 2 Compliance Scanner")
    st.markdown(
        "Click **Run Scan** in the sidebar to collect AWS evidence "
        "and assess SOC 2 control coverage."
    )
    st.stop()

results = st.session_state["results"]
ai_analysis = st.session_state.get("ai_analysis", {})
evidence = st.session_state.get("evidence", {})
coverage = results["coverage"]
scores = results["scores"]

st.title("Scan Results")

# -- Metric cards ---------------------------------------------------------

col1, col2, col3, col4 = st.columns(4)
col1.metric("Evidence Types", len(results["evidence_types"]))
col2.metric(
    "Controls Covered",
    f"{coverage['covered_count']}/{coverage['total_controls']}",
)
col3.metric("Freshness", f"{scores['freshness_score']}/100")
col4.metric("Risk Rating", ai_analysis.get("risk_rating", "N/A"))

st.divider()

# -- Tabs -----------------------------------------------------------------

tab_overview, tab_evidence, tab_ai, tab_report = st.tabs(
    ["Overview", "Evidence", "AI Analysis", "Report"]
)

# ---- Overview -----------------------------------------------------------
with tab_overview:
    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Control Coverage")
        covered_ids = list(coverage.get("covered", {}).keys())
        gap_ids = list(coverage.get("gaps", {}).keys())

        # Coverage bar via a simple dataframe
        import pandas as pd

        cov_df = pd.DataFrame(
            {"Category": ["Covered", "Gaps"], "Count": [len(covered_ids), len(gap_ids)]}
        )
        st.bar_chart(cov_df, x="Category", y="Count", color="Category")

        if covered_ids:
            st.markdown("**Covered:** " + ", ".join(covered_ids))
        if gap_ids:
            st.markdown("**Gaps:** " + ", ".join(gap_ids))

    with c2:
        st.subheader("Freshness Scores")
        details = scores.get("freshness_details", {})
        if details:
            df = pd.DataFrame(
                [
                    {
                        "Evidence": k,
                        "Score": v["score"],
                        "Age (h)": v.get("age_hours", "N/A"),
                        "Status": v["label"],
                    }
                    for k, v in details.items()
                ]
            )
            st.dataframe(df, use_container_width=True, hide_index=True)

# ---- Evidence -----------------------------------------------------------
with tab_evidence:
    st.subheader("Collected Evidence")
    for etype in sorted(evidence.keys()):
        detail = scores.get("freshness_details", {}).get(etype, {})
        label = detail.get("label", "unknown")
        score = detail.get("score", 0)
        with st.expander(f"{etype}  (freshness: {score}/100 -- {label})"):
            data = evidence[etype]
            if isinstance(data, dict):
                display = {k: v for k, v in data.items() if k != "collected_at"}
                st.json(display)
            else:
                st.json(data)

# ---- AI Analysis --------------------------------------------------------
with tab_ai:
    st.subheader("AI Policy Analysis")

    if not ai_analysis or not ai_analysis.get("findings"):
        st.info("No AI analysis available.")
    else:
        st.markdown(f"**Risk Rating:** {ai_analysis.get('risk_rating', 'N/A')}")
        st.markdown(ai_analysis.get("summary", ""))
        st.divider()

        for finding in ai_analysis["findings"]:
            severity = finding.get("severity", "INFO")
            icon = {"HIGH": "\u274c", "MEDIUM": "\u26a0\ufe0f", "LOW": "\u2139\ufe0f"}.get(
                severity, ""
            )
            st.markdown(
                f"{icon} **[{severity}] {finding['title']}** ({finding['control']})"
            )
            st.markdown(f"> {finding['description']}")
            st.markdown(f"_Recommendation: {finding['recommendation']}_")
            st.markdown("---")

# ---- Report -------------------------------------------------------------
with tab_report:
    st.subheader("Download Report")

    generator = PDFReportGenerator()
    pdf_bytes = generator.generate(results, ai_analysis)

    st.download_button(
        label="Download PDF Report",
        data=pdf_bytes,
        file_name="soc2_evidence_report.pdf",
        mime="application/pdf",
        type="primary",
    )

    st.divider()
    st.subheader("Raw JSON")
    st.json(results)
