"""Data models for the Evidence Tracer Agent."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class ClaimType(Enum):
    STATISTICAL = "statistical"
    MARKET = "market"
    FINANCIAL = "financial"
    COMPARATIVE = "comparative"
    CAUSAL = "causal"
    GENERAL = "general"


class EvidenceStrength(Enum):
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    CONTRADICTORY = "contradictory"
    NONE_FOUND = "none_found"


class SourceReliability(Enum):
    HIGH = "high"          # Gov, academic, major publications
    MEDIUM = "medium"      # Industry reports, established media
    LOW = "low"            # Blogs, forums, unknown sources
    UNKNOWN = "unknown"


@dataclass
class Claim:
    """A single claim extracted from a document."""
    id: int
    text: str
    claim_type: ClaimType
    context: str = ""           # Surrounding text for context
    source_line: int = 0        # Line number in original document
    keywords: list[str] = field(default_factory=list)

    def __str__(self):
        return f"[Claim #{self.id}] ({self.claim_type.value}) {self.text}"


@dataclass
class Source:
    """A source where evidence was found."""
    url: str
    title: str
    snippet: str
    domain: str = ""
    reliability: SourceReliability = SourceReliability.UNKNOWN
    accessed_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def __str__(self):
        return f"[{self.reliability.value.upper()}] {self.title} ({self.domain})"


@dataclass
class Evidence:
    """Evidence found for or against a claim."""
    claim_id: int
    source: Source
    relevant_text: str
    supports_claim: bool
    strength: EvidenceStrength
    confidence_score: float = 0.0  # 0.0 to 1.0

    def __str__(self):
        stance = "SUPPORTS" if self.supports_claim else "CONTRADICTS"
        return f"[{stance}] ({self.strength.value}) {self.relevant_text[:80]}..."


@dataclass
class ClaimVerification:
    """Complete verification result for a single claim."""
    claim: Claim
    evidence_list: list[Evidence] = field(default_factory=list)
    overall_score: float = 0.0       # 0.0 to 1.0
    overall_strength: EvidenceStrength = EvidenceStrength.NONE_FOUND
    verdict: str = "Unverified"
    summary: str = ""

    @property
    def supporting_count(self) -> int:
        return sum(1 for e in self.evidence_list if e.supports_claim)

    @property
    def contradicting_count(self) -> int:
        return sum(1 for e in self.evidence_list if not e.supports_claim)


@dataclass
class TraceReport:
    """Complete evidence trace report for a document."""
    document_name: str
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    total_claims: int = 0
    verifications: list[ClaimVerification] = field(default_factory=list)
    summary: str = ""

    @property
    def verified_count(self) -> int:
        return sum(
            1 for v in self.verifications
            if v.overall_strength != EvidenceStrength.NONE_FOUND
        )

    @property
    def avg_confidence(self) -> float:
        scores = [v.overall_score for v in self.verifications if v.overall_score > 0]
        return sum(scores) / len(scores) if scores else 0.0
