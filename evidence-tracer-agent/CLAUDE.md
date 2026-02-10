# CLAUDE.md

## Project: Evidence Tracer Agent

Automated agent for collecting SOC 2 compliance evidence from AWS environments, mapping findings to SOC 2 controls, scoring compliance posture, and generating reports.

## Architecture

- `src/aws_connectors/` - Connectors for AWS services (CloudTrail, Config, IAM, etc.)
- `src/evidence_collectors/` - Logic for gathering and normalizing evidence
- `src/soc2_mapping/` - Mapping evidence to SOC 2 Trust Service Criteria
- `src/scoring/` - Compliance scoring and gap analysis
- `src/reporting/` - Report generation (PDF, JSON, dashboard)

## Commands

- Run: `python -m src.main`
- Test: `pytest tests/`

## Conventions

- Python 3.10+
- Type hints on all public functions
- Config via `config/config.yaml` and environment variables
- Secrets in `.env` (never committed)
