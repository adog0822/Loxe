#!/usr/bin/env bash
# run_demo.sh - Run the Evidence Tracer Agent in demo mode
#
# This script sets up the environment and runs the agent with
# simulated data, requiring no AWS or OpenAI credentials.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo "  Evidence Tracer Agent - Demo Runner"
echo "============================================================"
echo

# Check if .env exists, create with DEMO_MODE=true if not
if [ ! -f .env ]; then
    echo "[SETUP] No .env file found. Creating with DEMO_MODE=true..."
    cat > .env << 'EOF'
# Evidence Tracer Agent environment variables
# Created automatically by run_demo.sh

DEMO_MODE=true

# To run in production mode, set DEMO_MODE=false and configure:
# AWS_ACCESS_KEY_ID=your-access-key
# AWS_SECRET_ACCESS_KEY=your-secret-key
# AWS_DEFAULT_REGION=us-east-1
# OPENAI_API_KEY=your-openai-key
EOF
    echo "[SETUP] Created .env with DEMO_MODE=true"
else
    echo "[SETUP] Found existing .env file"
    # Ensure DEMO_MODE is set to true for the demo run
    if grep -q "DEMO_MODE" .env; then
        echo "[SETUP] DEMO_MODE found in .env"
    else
        echo "[SETUP] Adding DEMO_MODE=true to .env"
        echo "DEMO_MODE=true" >> .env
    fi
fi

echo

# Set up Python virtual environment if needed
if [ ! -d "venv" ]; then
    echo "[SETUP] Creating Python virtual environment..."
    python3 -m venv venv
    echo "[SETUP] Virtual environment created"

    echo "[SETUP] Installing dependencies..."
    source venv/bin/activate
    if [ -f requirements.txt ]; then
        pip install -r requirements.txt 2>/dev/null || true
    fi
    # Install python-dotenv for .env loading
    pip install python-dotenv 2>/dev/null || true
    echo "[SETUP] Dependencies installed"
else
    echo "[SETUP] Virtual environment already exists"
    source venv/bin/activate
fi

echo
echo "------------------------------------------------------------"
echo "  Starting Evidence Tracer Agent (Demo Mode)"
echo "------------------------------------------------------------"
echo

# Ensure DEMO_MODE is set for this run
export DEMO_MODE=true

# Run the agent
python src/main.py

echo
echo "------------------------------------------------------------"
echo "  Demo complete! Check the data/ directory for output files."
echo "------------------------------------------------------------"
