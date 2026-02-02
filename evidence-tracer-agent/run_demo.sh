#!/usr/bin/env bash
# Run the Evidence Tracer Agent in demo mode (no AWS credentials needed).
set -euo pipefail

cd "$(dirname "$0")"

export DEMO_MODE=true
exec python -m src.main
