import os
from datetime import datetime

import openai


class OpenAIReporter:
    """Generate auditor-ready reports using OpenAI"""

    def __init__(self):
        self.client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

    def generate_report(self, evidence, scores):
        """Generate SOC 2 compliance report"""

        prompt = f"""
        You are a SOC 2 compliance auditor analyzing AWS evidence for a client.

        EVIDENCE SUMMARY:
        - {len(evidence.get('users', []))} IAM users analyzed
        - Evidence collected: {evidence.get('timestamp', 'Unknown')}
        - Mapped to controls: {', '.join(evidence.get('control_mappings', []))}

        SCORES:
        - Freshness Score: {scores['freshness']['score']}/100
        - Gap Detection Score: {scores['gap_detection']['score']}/100
        - Missing controls: {', '.join(scores['gap_detection']['missing_controls'])}

        Please generate a professional SOC 2 compliance report for an auditor with:

        1. EXECUTIVE SUMMARY (3-4 sentences)
        2. EVIDENCE OVERVIEW (what was collected and analyzed)
        3. CONTROL ASSESSMENT (for each of the 8 core SOC 2 controls)
        4. FINDINGS & RECOMMENDATIONS
        5. RISK ASSESSMENT (Low/Medium/High)
        6. NEXT STEPS FOR COMPLIANCE

        Format in Markdown with clear headings and bullet points.
        Be concise but thorough - this is for a real auditor review.
        """

        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a senior SOC 2 compliance auditor with 15+ years experience."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=2000
            )

            report = response.choices[0].message.content

            # Add metadata header
            metadata = f"""# SOC 2 Compliance Report - Evidence Tracer Agent

**Report Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Evidence Freshness:** {scores['freshness']['score']}/100
**Control Coverage:** {len(evidence.get('control_mappings', []))}/8 controls
**Status:** {'PASS' if scores['freshness']['score'] > 80 and scores['gap_detection']['score'] > 50 else 'REVIEW REQUIRED'}

---

"""

            return metadata + report

        except Exception as e:
            return f"# Error Generating Report\n\nUnable to generate report: {str(e)}"
