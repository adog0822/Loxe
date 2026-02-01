#!/usr/bin/env bash
#
# SOC 2 Evidence Tracer Agent - Demo Runner
# Runs the full pipeline in demo mode with synthetic IAM data.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "Installing dependencies..."
pip install -q -r requirements.txt 2>/dev/null || true

echo ""
export DEMO_MODE=true

python src/main.py
