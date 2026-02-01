# Loxe - Evidence Tracer Agent

An AI-powered agent that extracts verifiable claims from documents (pitch decks, research papers, business plans), searches for real-world evidence, scores credibility, and generates detailed verification reports.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the demo (uses built-in sample pitch deck)
python main.py demo

# 3. Trace claims in your own file
python main.py trace path/to/your/document.txt

# 4. Trace claims from inline text
python main.py trace --text "The global AI market is worth $150 billion"
```

## How It Works

The Evidence Tracer Agent runs a 4-step pipeline:

1. **Claim Extraction** - Scans your document and identifies verifiable claims (statistics, market data, financial figures, comparisons, causal assertions)
2. **Evidence Search** - Searches the web for each claim using DuckDuckGo (no API key required)
3. **Scoring & Verification** - Scores evidence using text similarity, keyword overlap, number matching, and source reliability ratings
4. **Report Generation** - Produces a detailed report in Markdown, JSON, or HTML format

## Usage

### Trace a file
```bash
python main.py trace samples/pitch_deck_sample.txt
python main.py trace samples/research_claims_sample.txt
```

### Choose output format
```bash
python main.py trace document.txt --format markdown   # default
python main.py trace document.txt --format json
python main.py trace document.txt --format html
```

### Inline text
```bash
python main.py trace --text "Solar energy costs have fallen 89% since 2010"
```

### Control search depth
```bash
python main.py trace document.txt --max-results 10    # more evidence per claim
python main.py trace document.txt --max-results 3     # faster, fewer sources
```

### Verbose mode
```bash
python main.py trace document.txt -v
```

### Skip saving report
```bash
python main.py trace document.txt --no-save
```

## Project Structure

```
Loxe/
├── main.py                        # CLI entry point
├── requirements.txt               # Python dependencies
├── .env.example                   # Environment variable template
├── evidence_tracer/
│   ├── __init__.py                # Package init
│   ├── agent.py                   # Main orchestrator agent
│   ├── config.py                  # Configuration management
│   ├── models.py                  # Data models (Claim, Evidence, Source, Report)
│   ├── extractor.py               # Claim extraction engine (pattern-based NLP)
│   ├── searcher.py                # Evidence search engine (DuckDuckGo)
│   ├── scorer.py                  # Evidence scoring (TF-IDF similarity, heuristics)
│   └── reporter.py                # Report generator (Markdown, JSON, HTML)
├── samples/
│   ├── pitch_deck_sample.txt      # Sample pitch deck for testing
│   └── research_claims_sample.txt # Sample research document
└── output/                        # Generated reports (git-ignored)
```

## What Gets Traced

The agent identifies and verifies these types of claims:

| Claim Type | Examples |
|------------|----------|
| **Statistical** | "grew 340% QoQ", "94% accuracy" |
| **Market** | "TAM of $1.81 trillion", "45% of all deals" |
| **Financial** | "$85,000 MRR", "gross margin is 82%" |
| **Comparative** | "5x faster than", "leading platform" |
| **Causal** | "leads to $4.5B in misallocated capital" |

## Evidence Scoring

Each piece of evidence is scored on four dimensions:

- **Text Similarity** (30%) - Cosine similarity between claim and evidence
- **Keyword Overlap** (30%) - How many claim keywords appear in the evidence
- **Number Matching** (20%) - Whether specific numbers from the claim appear in evidence
- **Source Reliability** (20%) - Domain credibility (gov/edu = high, major media = medium, blogs = low)

## Verdict Categories

| Verdict | Score | Meaning |
|---------|-------|---------|
| **Well-Supported** | >= 50% | Strong corroborating evidence from reliable sources |
| **Partially Supported** | >= 30% | Some relevant evidence found |
| **Weakly Supported** | >= 15% | Limited or tangential evidence |
| **Disputed** | N/A | More contradicting evidence than supporting |
| **Unverified** | < 15% | No relevant evidence found |

## Requirements

- Python 3.10+
- Internet connection (for evidence search)
- No API keys required for basic operation

## Optional Configuration

Copy `.env.example` to `.env` to customize settings:

```bash
cp .env.example .env
```

Available settings:
- `MAX_SEARCH_RESULTS` - Results per claim (default: 5)
- `SEARCH_TIMEOUT` - Search timeout in seconds (default: 10)
- `OUTPUT_DIR` - Where reports are saved (default: ./output)
- `DEFAULT_FORMAT` - Report format: markdown/json/html (default: markdown)
