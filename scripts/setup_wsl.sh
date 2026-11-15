#!/usr/bin/env bash
# AgentShield WSL2 setup script
# Run this from the project root inside WSL2 Ubuntu

set -e

echo "=== AgentShield Setup Script ==="
echo "Platform: $(uname -a)"

# ── Python virtual environment ──────────────────────────────────
echo ""
echo "[1/5] Setting up Python virtual environment..."
cd backend
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo "  Python deps installed."

# ── Create .env if missing ────────────────────────────────────
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "  Created .env from .env.example. Please review and update."
fi

# ── Initialize database ───────────────────────────────────────
echo ""
echo "[2/5] Initializing database..."
python -c "
import asyncio
import sys
sys.path.insert(0, '..')
from backend.database.database import init_db
asyncio.run(init_db())
print('  Database initialized.')
"

# ── Create test model ─────────────────────────────────────────
echo ""
echo "[3/5] Creating test ML model (for testing without CICIDS2017)..."
cd ..
python -m ml.create_test_model
echo "  Test model created."

# ── Frontend ──────────────────────────────────────────────────
echo ""
echo "[4/5] Installing frontend dependencies..."
cd frontend
npm install --silent
echo "  Frontend deps installed."
cd ..

# ── Network interfaces ────────────────────────────────────────
echo ""
echo "[5/5] Available network interfaces in WSL2:"
ip a | grep -E "^[0-9]+:|inet " | head -30

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Update backend/.env with your CAPTURE_INTERFACE"
echo "  2. Install Suricata: sudo apt install suricata"
echo "  3. Install Ollama: curl -fsSL https://ollama.ai/install.sh | sh"
echo "     Then: ollama pull llama3.2"
echo "  4. For real ML model: python -m ml.train --data-dir /path/to/cicids2017"
echo "  5. Start backend: cd backend && source .venv/bin/activate && uvicorn main:app --reload"
echo "  6. Start frontend: cd frontend && npm run dev"
