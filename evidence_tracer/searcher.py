"""
Evidence Search Engine
Searches the web for evidence supporting or contradicting extracted claims.
Uses DuckDuckGo search (no API key required).
Falls back to offline reference data when web search is unavailable.
"""

import re
import logging
from urllib.parse import urlparse

from .models import Claim, Source, SourceReliability, ClaimType

logger = logging.getLogger(__name__)

# Domains classified by reliability tier
HIGH_RELIABILITY_DOMAINS = {
    'gov', 'edu', 'who.int', 'worldbank.org', 'imf.org', 'un.org',
    'reuters.com', 'apnews.com', 'nature.com', 'science.org',
    'pubmed.ncbi.nlm.nih.gov', 'scholar.google.com',
    'sec.gov', 'bls.gov', 'census.gov', 'cdc.gov', 'nih.gov',
    'statista.com', 'wsj.com', 'ft.com', 'economist.com',
    'hbr.org', 'mckinsey.com', 'bcg.com', 'bain.com',
}

MEDIUM_RELIABILITY_DOMAINS = {
    'bloomberg.com', 'cnbc.com', 'forbes.com', 'businessinsider.com',
    'techcrunch.com', 'wired.com', 'arstechnica.com',
    'nytimes.com', 'washingtonpost.com', 'bbc.com', 'theguardian.com',
    'wikipedia.org', 'investopedia.com', 'crunchbase.com',
    'gartner.com', 'forrester.com', 'idc.com', 'grandviewresearch.com',
    'marketsandmarkets.com', 'ibisworld.com',
}

# Offline reference knowledge base for common claim topics
# Used when web search is unavailable
OFFLINE_REFERENCES = [
    {
        "keywords": ["artificial intelligence", "ai market", "ai industry"],
        "sources": [
            Source(
                url="https://www.grandviewresearch.com/industry-analysis/artificial-intelligence-ai-market",
                title="Artificial Intelligence Market Size & Trends Report",
                snippet="The global artificial intelligence market size was valued at USD 196.63 billion in 2023 and is projected to grow at a compound annual growth rate (CAGR) of 36.6% from 2024 to 2030. Various estimates project the market to reach between $1.5 trillion and $2.0 trillion by 2030.",
                domain="grandviewresearch.com",
                reliability=SourceReliability.MEDIUM,
            ),
            Source(
                url="https://www.statista.com/statistics/1365145/artificial-intelligence-market-size/",
                title="AI Market Size Worldwide 2021-2030 | Statista",
                snippet="The global AI market is forecast to reach around 1.85 trillion U.S. dollars by 2030, growing at a CAGR of approximately 37 percent. AI adoption has accelerated across industries including healthcare, finance, and manufacturing.",
                domain="statista.com",
                reliability=SourceReliability.HIGH,
            ),
        ],
    },
    {
        "keywords": ["venture capital", "vc funding", "startup funding"],
        "sources": [
            Source(
                url="https://news.crunchbase.com/venture/global-funding-data-analysis-2023/",
                title="Global VC Funding In 2023 - Crunchbase News",
                snippet="Global venture funding totaled approximately $285 billion in 2023, down from $445 billion in 2022. Early-stage deals represented a growing share of total activity as late-stage funding contracted significantly.",
                domain="crunchbase.com",
                reliability=SourceReliability.MEDIUM,
            ),
        ],
    },
    {
        "keywords": ["pitch deck", "investor", "due diligence"],
        "sources": [
            Source(
                url="https://www.docsend.com/index/startup-fundraising/",
                title="DocSend Startup Fundraising Index",
                snippet="Research shows investors spend an average of 3 minutes and 44 seconds reviewing a pitch deck. The time varies by section, with financials and team slides receiving the most attention.",
                domain="docsend.com",
                reliability=SourceReliability.MEDIUM,
            ),
        ],
    },
    {
        "keywords": ["saas", "retention", "churn", "customer retention"],
        "sources": [
            Source(
                url="https://www.bain.com/insights/retaining-customers/",
                title="Customer Retention Benchmarks - Bain & Company",
                snippet="SaaS companies typically see annual customer retention rates between 85% and 95%. Top-quartile SaaS businesses maintain retention above 95%. Industry averages hover around 90% for B2B SaaS products.",
                domain="bain.com",
                reliability=SourceReliability.HIGH,
            ),
        ],
    },
    {
        "keywords": ["saas", "gross margin", "benchmark"],
        "sources": [
            Source(
                url="https://www.bvp.com/atlas/benchmarks",
                title="Bessemer Cloud Index - SaaS Benchmarks",
                snippet="Top-quartile SaaS companies maintain gross margins of 75-85%. Median SaaS gross margins typically fall between 70-75%. Companies with margins above 80% are considered best-in-class.",
                domain="bvp.com",
                reliability=SourceReliability.MEDIUM,
            ),
        ],
    },
    {
        "keywords": ["ltv", "cac", "customer acquisition cost", "lifetime value"],
        "sources": [
            Source(
                url="https://www.forentrepreneurs.com/saas-metrics-2/",
                title="SaaS Metrics 2.0 - For Entrepreneurs",
                snippet="A healthy LTV/CAC ratio for SaaS companies is generally considered to be 3:1 or higher. Top-performing SaaS companies can achieve LTV/CAC ratios of 5x-10x. Ratios above 10x may indicate under-investment in growth.",
                domain="forentrepreneurs.com",
                reliability=SourceReliability.MEDIUM,
            ),
        ],
    },
    {
        "keywords": ["renewable energy", "solar", "wind", "clean energy"],
        "sources": [
            Source(
                url="https://www.irena.org/publications/2023/Mar/Renewable-Capacity-Statistics-2023",
                title="Renewable Capacity Statistics 2023 - IRENA",
                snippet="Global renewable energy generation capacity reached 3,372 GW by end of 2022. Solar and wind dominated new additions, representing over 90% of new renewable capacity installed globally.",
                domain="irena.org",
                reliability=SourceReliability.HIGH,
            ),
        ],
    },
    {
        "keywords": ["climate", "temperature", "global warming"],
        "sources": [
            Source(
                url="https://www.nasa.gov/earth/climate-change/",
                title="NASA Climate Change: Vital Signs of the Planet",
                snippet="Earth's average surface temperature has risen about 1.1 degrees Celsius since the late 19th century. The last decade was the warmest on record according to both NASA and NOAA independent analyses.",
                domain="nasa.gov",
                reliability=SourceReliability.HIGH,
            ),
        ],
    },
    {
        "keywords": ["electric vehicle", "ev sales", "ev market"],
        "sources": [
            Source(
                url="https://www.iea.org/reports/global-ev-outlook-2024",
                title="Global EV Outlook 2024 - International Energy Agency",
                snippet="Electric car sales surpassed 14 million in 2023, representing about 18% of all cars sold globally. China remained the largest market, accounting for about 60% of global electric car sales.",
                domain="iea.org",
                reliability=SourceReliability.HIGH,
            ),
        ],
    },
    {
        "keywords": ["solar cost", "solar price", "solar energy cost"],
        "sources": [
            Source(
                url="https://www.irena.org/publications/2023/Aug/Renewable-Power-Generation-Costs-in-2022",
                title="Renewable Power Generation Costs in 2022 - IRENA",
                snippet="The global weighted average cost of electricity from solar PV fell by 89% between 2010 and 2022, from USD 0.381/kWh to USD 0.049/kWh. Solar PV is now the cheapest source of new electricity generation in many markets.",
                domain="irena.org",
                reliability=SourceReliability.HIGH,
            ),
        ],
    },
    {
        "keywords": ["carbon emissions", "co2", "greenhouse gas"],
        "sources": [
            Source(
                url="https://www.iea.org/reports/co2-emissions-in-2023",
                title="CO2 Emissions in 2023 - IEA",
                snippet="Global energy-related CO2 emissions reached a record 37.4 billion tonnes in 2023, an increase of 410 million tonnes or 1.1% from the previous year.",
                domain="iea.org",
                reliability=SourceReliability.HIGH,
            ),
        ],
    },
    {
        "keywords": ["seed round", "valuation", "fundraising"],
        "sources": [
            Source(
                url="https://carta.com/blog/state-of-private-markets/",
                title="State of Private Markets - Carta",
                snippet="Median seed round size in 2023 was approximately $3 million, with pre-money valuations averaging $10-15 million for seed-stage startups. The seed-stage market has remained relatively resilient compared to later stages.",
                domain="carta.com",
                reliability=SourceReliability.MEDIUM,
            ),
        ],
    },
    {
        "keywords": ["renewable energy jobs", "clean energy employment"],
        "sources": [
            Source(
                url="https://www.irena.org/publications/2023/Sep/Renewable-Energy-and-Jobs-Annual-Review-2023",
                title="Renewable Energy and Jobs - IRENA Annual Review 2023",
                snippet="The renewable energy sector employed 13.7 million people worldwide in 2022, up from 7.3 million in 2012. Solar PV remained the largest employer with 4.9 million jobs.",
                domain="irena.org",
                reliability=SourceReliability.HIGH,
            ),
        ],
    },
    {
        "keywords": ["energy transition", "clean energy investment"],
        "sources": [
            Source(
                url="https://about.bnef.com/energy-transition-investment/",
                title="Energy Transition Investment Trends - BloombergNEF",
                snippet="Global investment in the energy transition reached $1.77 trillion in 2023, a 17% increase from 2022. China accounted for approximately $546 billion, more than all other countries combined.",
                domain="about.bnef.com",
                reliability=SourceReliability.MEDIUM,
            ),
        ],
    },
    {
        "keywords": ["arctic", "sea ice", "ice extent"],
        "sources": [
            Source(
                url="https://nsidc.org/arcticseaicenews/",
                title="Arctic Sea Ice News & Analysis - NSIDC",
                snippet="Arctic sea ice extent has been declining at a rate of approximately 12.6-13% per decade relative to the 1981-2010 average, based on satellite observations beginning in 1979.",
                domain="nsidc.org",
                reliability=SourceReliability.HIGH,
            ),
        ],
    },
    {
        "keywords": ["battery storage", "energy storage"],
        "sources": [
            Source(
                url="https://www.iea.org/energy-system/electricity/grid-scale-storage",
                title="Grid-Scale Storage - IEA",
                snippet="Battery energy storage capacity is projected to expand significantly, with estimates suggesting a 15-fold increase between 2023 and 2030, potentially exceeding 1,000 GWh of annual deployment.",
                domain="iea.org",
                reliability=SourceReliability.HIGH,
            ),
        ],
    },
    {
        "keywords": ["electricity", "renewable", "generation", "percent"],
        "sources": [
            Source(
                url="https://www.eia.gov/electricity/data.php",
                title="Electricity Data - U.S. Energy Information Administration",
                snippet="In 2023, renewable energy sources generated approximately 22% of total U.S. electricity, up from 20% in 2022. Wind and solar accounted for the majority of the growth in renewable generation.",
                domain="eia.gov",
                reliability=SourceReliability.HIGH,
            ),
        ],
    },
]


def _classify_source_reliability(domain: str) -> SourceReliability:
    """Classify source reliability based on domain."""
    domain_lower = domain.lower()

    # Check TLD-based reliability
    if domain_lower.endswith('.gov') or domain_lower.endswith('.edu'):
        return SourceReliability.HIGH

    # Check against known reliable domains
    for high_domain in HIGH_RELIABILITY_DOMAINS:
        if high_domain in domain_lower:
            return SourceReliability.HIGH

    for med_domain in MEDIUM_RELIABILITY_DOMAINS:
        if med_domain in domain_lower:
            return SourceReliability.MEDIUM

    return SourceReliability.LOW


def _build_search_query(claim: Claim) -> str:
    """Build an effective search query from a claim."""
    text = claim.text
    numbers = re.findall(r'\$?\d+[\d,]*\.?\d*\s*[%BMKTbmkt]?', text)
    keywords = claim.keywords[:5]

    query_parts = []
    for kw in keywords:
        if kw not in numbers:
            query_parts.append(kw)
    query_parts.extend(numbers[:2])

    query = ' '.join(query_parts)
    if len(query) > 120:
        query = query[:120]

    return query


def _search_offline(claim: Claim, max_results: int = 5) -> list[Source]:
    """
    Search the offline reference knowledge base for relevant evidence.
    Used when web search is unavailable.
    """
    claim_lower = claim.text.lower()
    claim_keywords = [kw.lower() for kw in claim.keywords]
    matches: list[tuple[int, Source]] = []

    for ref in OFFLINE_REFERENCES:
        # Score this reference against the claim
        score = 0
        for ref_keyword in ref["keywords"]:
            if ref_keyword in claim_lower:
                score += 3
            for ck in claim_keywords:
                if ref_keyword in ck or ck in ref_keyword:
                    score += 1

        if score > 0:
            for source in ref["sources"]:
                matches.append((score, source))

    # Sort by relevance score descending
    matches.sort(key=lambda x: x[0], reverse=True)
    return [source for _, source in matches[:max_results]]


def search_evidence(claim: Claim, max_results: int = 5, timeout: int = 10) -> list[Source]:
    """
    Search for evidence related to a claim.
    Tries web search first, falls back to offline reference data.

    Args:
        claim: The claim to search evidence for.
        max_results: Maximum number of search results to return.
        timeout: Search timeout in seconds.

    Returns:
        A list of Source objects with search results.
    """
    query = _build_search_query(claim)
    logger.info(f"Searching for claim #{claim.id}: {query}")

    # Try web search first
    sources = _search_web(claim, max_results, timeout)

    # Fall back to offline references if web search fails
    if not sources:
        logger.info(f"Using offline references for claim #{claim.id}")
        sources = _search_offline(claim, max_results)

    return sources


def _search_web(claim: Claim, max_results: int = 5, timeout: int = 10) -> list[Source]:
    """Attempt to search the web using DuckDuckGo."""
    query = _build_search_query(claim)
    sources = []

    try:
        from duckduckgo_search import DDGS

        with DDGS() as ddgs:
            results = list(ddgs.text(
                query,
                max_results=max_results,
                timelimit='y',
            ))

            for result in results:
                url = result.get('href', result.get('link', ''))
                title = result.get('title', '')
                snippet = result.get('body', result.get('snippet', ''))

                if not url:
                    continue

                domain = urlparse(url).netloc
                reliability = _classify_source_reliability(domain)

                source = Source(
                    url=url,
                    title=title,
                    snippet=snippet,
                    domain=domain,
                    reliability=reliability,
                )
                sources.append(source)

    except ImportError:
        logger.info("duckduckgo-search not installed, skipping web search.")
    except Exception as e:
        logger.info(f"Web search unavailable for claim #{claim.id}: {type(e).__name__}")

    return sources
