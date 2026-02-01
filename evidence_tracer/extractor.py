"""
Claim Extraction Engine
Extracts verifiable claims from text documents using pattern-based NLP heuristics.
No external API key required for basic operation.
"""

import re
from .models import Claim, ClaimType


# Patterns that indicate statistical/quantitative claims
STAT_PATTERNS = [
    r'\d+\.?\d*\s*%',                          # percentages
    r'\$\s*\d+[\d,]*\.?\d*\s*[BMKTbmkt]?',    # dollar amounts
    r'\d+[\d,]*\.?\d*\s*(billion|million|thousand|trillion)',  # large numbers
    r'(grew|growth|increase|decrease|decline|rose|fell)\s+.*?\d+',  # growth metrics
    r'\d+x\s',                                  # multipliers
    r'(CAGR|YoY|MoM|QoQ).*?\d+',              # business metrics
]

# Patterns that indicate market claims
MARKET_PATTERNS = [
    r'(market\s+size|TAM|SAM|SOM).*?\$?\d+',
    r'(market\s+share|market\s+cap)',
    r'(addressable\s+market|target\s+market).*?\d+',
    r'\d+.*?(users|customers|clients|subscribers|downloads)',
    r'(industry|sector|market)\s+(is|was|will|projected)',
]

# Patterns that indicate financial claims
FINANCIAL_PATTERNS = [
    r'(revenue|ARR|MRR|GMV|burn\s+rate).*?\$?\d+',
    r'(profit|margin|EBITDA|valuation).*?\d+',
    r'(raised|funding|investment|round).*?\$?\d+',
    r'(runway|break-?even).*?\d+',
]

# Patterns that indicate comparative claims
COMPARATIVE_PATTERNS = [
    r'(faster|slower|better|worse|more|less|cheaper|larger|smaller)\s+than',
    r'(leading|largest|fastest|first|only|best|top)\s',
    r'(outperform|surpass|exceed|beat)',
    r'(compared\s+to|versus|vs\.?)\s',
    r'(unlike|in\s+contrast)',
]

# Patterns that indicate causal claims
CAUSAL_PATTERNS = [
    r'(because|therefore|thus|consequently|as\s+a\s+result)',
    r'(leads?\s+to|results?\s+in|causes?|drives?)',
    r'(due\s+to|owing\s+to|thanks\s+to)',
    r'(enables?|allows?|ensures?)\s+.*?(growth|increase|improvement)',
]

# Sentence-ending patterns
SENTENCE_END = re.compile(r'[.!?]\s+|[.!?]$|\n')

# Words that indicate a claim is being made
CLAIM_INDICATORS = [
    'is', 'are', 'was', 'were', 'will', 'has', 'have', 'had',
    'shows', 'demonstrates', 'proves', 'indicates', 'suggests',
    'according to', 'research shows', 'studies show', 'data shows',
    'projected', 'estimated', 'expected', 'forecast',
]


def _extract_sentences(text: str) -> list[tuple[str, int]]:
    """Split text into sentences with their line numbers."""
    lines = text.split('\n')
    sentences = []
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        # Split line into sentences
        parts = SENTENCE_END.split(line)
        for part in parts:
            part = part.strip()
            if len(part) > 15:  # Skip very short fragments
                sentences.append((part, line_num))
    return sentences


def _classify_claim(text: str) -> ClaimType:
    """Classify a claim by its type based on pattern matching."""
    text_lower = text.lower()

    for pattern in STAT_PATTERNS:
        if re.search(pattern, text_lower):
            return ClaimType.STATISTICAL

    for pattern in FINANCIAL_PATTERNS:
        if re.search(pattern, text_lower):
            return ClaimType.FINANCIAL

    for pattern in MARKET_PATTERNS:
        if re.search(pattern, text_lower):
            return ClaimType.MARKET

    for pattern in COMPARATIVE_PATTERNS:
        if re.search(pattern, text_lower):
            return ClaimType.COMPARATIVE

    for pattern in CAUSAL_PATTERNS:
        if re.search(pattern, text_lower):
            return ClaimType.CAUSAL

    return ClaimType.GENERAL


def _is_verifiable_claim(text: str) -> bool:
    """Determine if a sentence contains a verifiable claim."""
    text_lower = text.lower()

    # Must have some substance
    if len(text.split()) < 5:
        return False

    # Check for quantitative indicators (strong signal)
    all_patterns = STAT_PATTERNS + FINANCIAL_PATTERNS + MARKET_PATTERNS
    for pattern in all_patterns:
        if re.search(pattern, text_lower):
            return True

    # Check for comparative/causal claims
    for pattern in COMPARATIVE_PATTERNS + CAUSAL_PATTERNS:
        if re.search(pattern, text_lower):
            return True

    # Check for claim indicator words with factual assertions
    has_indicator = any(ind in text_lower for ind in CLAIM_INDICATORS)
    has_specifics = bool(re.search(r'\d+|specific|particular|exact', text_lower))

    return has_indicator and has_specifics


def _extract_keywords(text: str) -> list[str]:
    """Extract search keywords from a claim."""
    # Remove common stopwords
    stopwords = {
        'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
        'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
        'should', 'may', 'might', 'can', 'shall', 'to', 'of', 'in', 'for',
        'on', 'with', 'at', 'by', 'from', 'as', 'into', 'through', 'during',
        'before', 'after', 'above', 'below', 'between', 'and', 'but', 'or',
        'not', 'no', 'nor', 'so', 'yet', 'both', 'each', 'few', 'more',
        'most', 'other', 'some', 'such', 'than', 'too', 'very', 'just',
        'about', 'its', 'our', 'their', 'this', 'that', 'these', 'those',
        'it', 'we', 'they', 'them', 'he', 'she', 'his', 'her',
    }

    words = re.findall(r'[A-Za-z]+(?:[-\'][A-Za-z]+)*', text)
    keywords = []
    for w in words:
        if w.lower() not in stopwords and len(w) > 2:
            keywords.append(w)

    # Also extract numbers and percentages as keywords
    numbers = re.findall(r'\$?\d+[\d,]*\.?\d*\s*[%BMKTbmkt]?', text)
    keywords.extend(numbers)

    return keywords[:10]  # Limit to top 10 keywords


def extract_claims(text: str) -> list[Claim]:
    """
    Extract verifiable claims from a text document.

    Args:
        text: The full text of the document to analyze.

    Returns:
        A list of Claim objects extracted from the text.
    """
    sentences = _extract_sentences(text)
    claims = []
    claim_id = 1

    for sentence, line_num in sentences:
        if _is_verifiable_claim(sentence):
            claim_type = _classify_claim(sentence)
            keywords = _extract_keywords(sentence)

            claim = Claim(
                id=claim_id,
                text=sentence.strip(),
                claim_type=claim_type,
                source_line=line_num,
                keywords=keywords,
            )
            claims.append(claim)
            claim_id += 1

    return claims
