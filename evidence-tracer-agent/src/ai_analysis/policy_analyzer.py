"""AI-powered IAM policy analysis using the Claude API."""

import json
import os
from typing import Any


DEMO_ANALYSIS: dict[str, Any] = {
    "findings": [
        {
            "severity": "HIGH",
            "control": "CC6.7",
            "title": "Overly Permissive Admin Policy",
            "description": (
                "The policy 'AdminFullAccess' grants Action: * on Resource: * and is "
                "attached directly to user 'admin-user'. This violates the principle "
                "of least privilege required by CC6.7."
            ),
            "recommendation": (
                "Replace the wildcard policy with scoped permissions per service. "
                "Attach policies to groups or roles instead of directly to users. "
                "Use AWS Access Analyzer to identify actually-used permissions."
            ),
        },
        {
            "severity": "MEDIUM",
            "control": "CC6.1",
            "title": "MFA Not Enabled for All Console Users",
            "description": (
                "Users 'service-account' and 'stale-user' do not have MFA enabled. "
                "While service accounts may not need console access, 'stale-user' "
                "has console login history, creating an authentication gap."
            ),
            "recommendation": (
                "Enforce MFA for all users with console access via an IAM policy "
                "condition on aws:MultiFactorAuthPresent. Disable console access "
                "for service accounts that only need programmatic access."
            ),
        },
        {
            "severity": "MEDIUM",
            "control": "CC6.3",
            "title": "Stale Access Keys Without Rotation",
            "description": (
                "User 'service-account' has two active access keys, one of which "
                "was created 200 days ago and last used 150 days ago. User "
                "'stale-user' has a key created 400+ days ago. Neither has been "
                "rotated within the 90-day best practice window."
            ),
            "recommendation": (
                "Implement automated key rotation with a maximum age of 90 days. "
                "Deactivate the unused key for 'service-account' immediately. "
                "Use AWS Secrets Manager for automated rotation of service keys."
            ),
        },
        {
            "severity": "LOW",
            "control": "CC6.1",
            "title": "Inactive User Account Detected",
            "description": (
                "User 'stale-user' has not logged in for 95 days and has an "
                "active access key. Dormant accounts with active credentials "
                "increase the attack surface."
            ),
            "recommendation": (
                "Establish an automated process to detect accounts inactive for "
                "90+ days. Disable credentials and notify the account owner. "
                "Remove the account if no response within 14 days."
            ),
        },
    ],
    "summary": (
        "Analysis identified 4 findings across 3 SOC 2 controls. One high-severity "
        "issue (overly permissive admin policy) requires immediate attention. Two "
        "medium-severity issues involve incomplete MFA enforcement and stale access "
        "keys. The IAM configuration shows a common pattern of initially broad "
        "permissions that have not been tightened as the organization matured."
    ),
    "risk_rating": "MEDIUM-HIGH",
}


def analyze_policies(evidence: dict[str, Any]) -> dict[str, Any]:
    """Analyze IAM evidence for SOC 2 compliance using AI.

    In DEMO_MODE or when no API key is configured, returns pre-built analysis.
    In live mode, calls the Claude API for real analysis.
    """
    demo_mode = os.environ.get("DEMO_MODE", "").lower() in ("true", "1", "yes")

    if demo_mode:
        print("[AI Analyzer] Running in DEMO_MODE - using pre-built analysis")
        return DEMO_ANALYSIS

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[AI Analyzer] WARNING: No ANTHROPIC_API_KEY set, using demo analysis")
        return DEMO_ANALYSIS

    return _call_claude(evidence, api_key)


def _call_claude(evidence: dict[str, Any], api_key: str) -> dict[str, Any]:
    """Call the Claude API to analyze IAM policies for SOC 2 compliance."""
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)

    # Build context from the evidence most relevant to policy analysis
    relevant_keys = (
        "iam_policies",
        "overly_permissive_policies",
        "mfa_status",
        "access_keys",
        "password_policy",
        "iam_users",
    )
    policy_context = json.dumps(
        {k: v for k, v in evidence.items() if k in relevant_keys},
        indent=2,
        default=str,
    )

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        messages=[
            {
                "role": "user",
                "content": (
                    "You are a SOC 2 compliance analyst. Analyze the following AWS "
                    "IAM evidence and return a JSON object with exactly this schema:\n"
                    "{\n"
                    '  "findings": [\n'
                    "    {\n"
                    '      "severity": "HIGH|MEDIUM|LOW",\n'
                    '      "control": "CC6.x",\n'
                    '      "title": "Short title",\n'
                    '      "description": "What is wrong and why it matters",\n'
                    '      "recommendation": "Specific remediation steps"\n'
                    "    }\n"
                    "  ],\n"
                    '  "summary": "Overall assessment paragraph",\n'
                    '  "risk_rating": "LOW|MEDIUM|MEDIUM-HIGH|HIGH|CRITICAL"\n'
                    "}\n\n"
                    "Focus on SOC 2 Trust Service Criteria:\n"
                    "- CC6.1 (Logical Access)\n"
                    "- CC6.3 (Access Key Management)\n"
                    "- CC6.7 (Least Privilege)\n\n"
                    "Return only valid JSON, no markdown fences.\n\n"
                    f"Evidence:\n{policy_context}"
                ),
            }
        ],
    )

    text = response.content[0].text

    try:
        # Handle case where model wraps JSON in markdown fences
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]
        return json.loads(text.strip())
    except (json.JSONDecodeError, IndexError):
        return {
            "findings": [],
            "summary": text,
            "risk_rating": "UNKNOWN",
        }
