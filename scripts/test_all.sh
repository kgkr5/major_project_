#!/usr/bin/env bash
# Run all AgentShield backend tests with coverage

set -e
cd "$(dirname "$0")/.."

source backend/.venv/bin/activate 2>/dev/null || true

echo "=== Running AgentShield tests ==="
cd backend

pytest tests/ \
  --cov=. \
  --cov-report=term-missing \
  --cov-report=html:htmlcov \
  --cov-omit="tests/*,*__init__*" \
  -v \
  "$@"

echo ""
echo "Coverage report: backend/htmlcov/index.html"
