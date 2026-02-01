# Evidence Tracer Agent

Automated SOC 2 evidence collection and compliance scoring agent.

## Project Structure

```
evidence-tracer-agent/
├── src/
│   ├── aws_connectors/      # AWS service connectors
│   ├── evidence_collectors/  # Evidence collection logic
│   ├── soc2_mapping/         # SOC 2 control mapping
│   ├── scoring/              # Compliance scoring engine
│   └── reporting/            # Report generation
├── config/                   # Configuration files
├── tests/                    # Test suite
├── docs/                     # Documentation
└── data/                     # Data files
```

## Setup

1. Copy `.env.example` to `.env` and configure your credentials
2. Install dependencies: `pip install -r requirements.txt`
3. Run: `python -m src.main`
