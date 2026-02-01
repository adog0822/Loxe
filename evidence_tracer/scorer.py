"""
Evidence Scoring Engine
Analyzes and scores evidence against claims using text similarity and heuristics.
"""

import re
import math
import logging
from collections import Counter

from .models import (
    Claim, Source, Evidence, EvidenceStrength,
    ClaimVerification, SourceReliability,
)

logger = logging.getLogger(__name__)


def _tokenize(text: str) -> list[str]:
    """Simple tokenization: lowercase words."""
    return re.findall(r'[a-z]+(?:[-\'][a-z]+)*|\d+\.?\d*', text.lower())


def _compute_tf(tokens: list[str]) -> dict[str, float]:
    """Compute term frequency."""
    counts = Counter(tokens)
    total = len(tokens)
    if total == 0:
        return {}
    return {term: count / total for term, count in counts.items()}


def _cosine_similarity(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
    """Compute cosine similarity between two term-frequency vectors."""
    common_terms = set(vec_a.keys()) & set(vec_b.keys())
    if not common_terms:
        return 0.0

    dot_product = sum(vec_a[t] * vec_b[t] for t in common_terms)
    mag_a = math.sqrt(sum(v ** 2 for v in vec_a.values()))
    mag_b = math.sqrt(sum(v ** 2 for v in vec_b.values()))

    if mag_a == 0 or mag_b == 0:
        return 0.0

    return dot_product / (mag_a * mag_b)


def _keyword_overlap_score(claim: Claim, text: str) -> float:
    """Score based on how many claim keywords appear in the evidence text."""
    text_lower = text.lower()
    if not claim.keywords:
        return 0.0

    matches = sum(1 for kw in claim.keywords if kw.lower() in text_lower)
    return matches / len(claim.keywords)


def _number_match_score(claim_text: str, evidence_text: str) -> float:
    """Score based on matching numbers between claim and evidence."""
    claim_numbers = set(re.findall(r'\d+\.?\d*', claim_text))
    evidence_numbers = set(re.findall(r'\d+\.?\d*', evidence_text))

    if not claim_numbers:
        return 0.5  # Neutral if no numbers to compare

    matches = claim_numbers & evidence_numbers
    return len(matches) / len(claim_numbers) if claim_numbers else 0.0


def _source_reliability_weight(reliability: SourceReliability) -> float:
    """Weight factor based on source reliability."""
    weights = {
        SourceReliability.HIGH: 1.0,
        SourceReliability.MEDIUM: 0.7,
        SourceReliability.LOW: 0.4,
        SourceReliability.UNKNOWN: 0.3,
    }
    return weights.get(reliability, 0.3)


def _detect_contradiction(claim_text: str, evidence_text: str) -> bool:
    """Simple heuristic to detect if evidence contradicts a claim."""
    evidence_lower = evidence_text.lower()

    # Strong contradiction signals — words that explicitly negate/dispute
    strong_signals = [
        'contrary', 'incorrect', 'false', 'misleading',
        'debunked', 'myth', 'not true', 'inaccurate', 'overstated',
        'exaggerated', 'correction', 'disputed', 'refuted',
    ]

    strong_count = sum(1 for signal in strong_signals if signal in evidence_lower)
    if strong_count >= 1:
        return True

    return False


def score_evidence(claim: Claim, source: Source) -> Evidence:
    """
    Score a single piece of evidence against a claim.

    Args:
        claim: The claim being verified.
        source: The source containing potential evidence.

    Returns:
        An Evidence object with scoring.
    """
    snippet = source.snippet

    # Compute multiple similarity signals
    claim_tokens = _tokenize(claim.text)
    snippet_tokens = _tokenize(snippet)

    claim_tf = _compute_tf(claim_tokens)
    snippet_tf = _compute_tf(snippet_tokens)

    # 1. Text similarity (cosine)
    text_sim = _cosine_similarity(claim_tf, snippet_tf)

    # 2. Keyword overlap
    keyword_score = _keyword_overlap_score(claim, snippet)

    # 3. Number matching
    number_score = _number_match_score(claim.text, snippet)

    # 4. Source reliability weight
    reliability_weight = _source_reliability_weight(source.reliability)

    # 5. Check for contradiction
    is_contradictory = _detect_contradiction(claim.text, snippet)

    # Compute composite confidence score
    raw_score = (
        text_sim * 0.30 +
        keyword_score * 0.30 +
        number_score * 0.20 +
        reliability_weight * 0.20
    )

    # Determine if evidence supports or contradicts
    supports = not is_contradictory

    # Classify evidence strength
    if raw_score >= 0.6:
        strength = EvidenceStrength.STRONG
    elif raw_score >= 0.35:
        strength = EvidenceStrength.MODERATE
    elif raw_score >= 0.15:
        strength = EvidenceStrength.WEAK
    else:
        strength = EvidenceStrength.NONE_FOUND

    if is_contradictory:
        strength = EvidenceStrength.CONTRADICTORY

    return Evidence(
        claim_id=claim.id,
        source=source,
        relevant_text=snippet,
        supports_claim=supports,
        strength=strength,
        confidence_score=round(raw_score, 3),
    )


def verify_claim(claim: Claim, sources: list[Source]) -> ClaimVerification:
    """
    Verify a claim against multiple sources and produce a verification result.

    Args:
        claim: The claim to verify.
        sources: List of sources found for this claim.

    Returns:
        A ClaimVerification with overall assessment.
    """
    evidence_list = []
    for source in sources:
        evidence = score_evidence(claim, source)
        evidence_list.append(evidence)

    # Sort by confidence score descending
    evidence_list.sort(key=lambda e: e.confidence_score, reverse=True)

    # Calculate overall score
    if evidence_list:
        # Weighted average favoring higher-confidence evidence
        weights = [1.0 / (i + 1) for i in range(len(evidence_list))]
        total_weight = sum(weights)
        overall_score = sum(
            e.confidence_score * w
            for e, w in zip(evidence_list, weights)
        ) / total_weight
    else:
        overall_score = 0.0

    # Determine overall strength
    supporting = [e for e in evidence_list if e.supports_claim]
    contradicting = [e for e in evidence_list if not e.supports_claim]

    if not evidence_list:
        overall_strength = EvidenceStrength.NONE_FOUND
        verdict = "Unverified - No evidence found"
    elif len(contradicting) > len(supporting):
        overall_strength = EvidenceStrength.CONTRADICTORY
        verdict = "Disputed - More contradicting evidence found"
    elif overall_score >= 0.5:
        overall_strength = EvidenceStrength.STRONG
        verdict = "Well-Supported - Strong corroborating evidence"
    elif overall_score >= 0.3:
        overall_strength = EvidenceStrength.MODERATE
        verdict = "Partially Supported - Some corroborating evidence"
    elif overall_score >= 0.15:
        overall_strength = EvidenceStrength.WEAK
        verdict = "Weakly Supported - Limited evidence found"
    else:
        overall_strength = EvidenceStrength.NONE_FOUND
        verdict = "Unverified - Insufficient relevant evidence"

    # Build summary
    summary = (
        f"Found {len(evidence_list)} source(s): "
        f"{len(supporting)} supporting, {len(contradicting)} contradicting. "
        f"Overall confidence: {overall_score:.1%}."
    )

    return ClaimVerification(
        claim=claim,
        evidence_list=evidence_list,
        overall_score=round(overall_score, 3),
        overall_strength=overall_strength,
        verdict=verdict,
        summary=summary,
    )
