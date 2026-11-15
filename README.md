# AgentShield

## A Multi-Agent AI Framework for Attack-Path Verification and Autonomous Cyber Defense

AgentShield is a complete cybersecurity monitoring platform that monitors authorized network traffic, identifies suspicious activity, detects potential attacks, analyzes attack paths, calculates risk levels, and provides defensive recommendations — operating like a lightweight Security Operations Center (SOC).

---

## Architecture

```
Authorized Network Traffic
        │
        ▼
  Packet Capture (Scapy/Rotating PCAP)
        │
   ┌────┴────┐
   │         │
   ▼         ▼
Suricata   CICFlowMeter-compatible
IDS/IPS    Flow Extractor (Python/dpkt)
   │         │
EVE JSON   77 Network Features
   │         │
   └────┬────┘
        │
   Feature Normalizer
        │
   Random Forest Classifier
   (BENIGN / ATTACK)
        │
   [AGENT 1] Detection Agent
        │
   [AGENT 2] Attack Analysis Agent ◄── Ollama (Llama 3.2)
        │
   [AGENT 3] Defence Agent
   (Recommendation-only mode)
        │
   SQLite Database (SQLAlchemy)
        │
   FastAPI (REST + WebSocket)
        │
   React SOC Dashboard
```

---

## Prerequisites

| Component | Required | Notes |
|-----------|----------|-------|
| Python 3.10+ | Required | WSL2 Ubuntu recommended |
| Node.js 20+ | Required | For frontend |
| WSL2 Ubuntu | Recommended | For packet capture |
| Suricata | Optional | IDS alerts |
| Ollama | Optional | LLM explanations |
| CICIDS2017 dataset | For training | ~2GB CSV files |

---

## Installation

### 1. Clone and set up (WSL2 Ubuntu)

```bash
# From project root
chmod +x scripts/setup_wsl.sh
./scripts/setup_wsl.sh
```

This will:
- Create Python virtual environment
- Install all backend dependencies
- Create `.env` from template
- Initialize SQLite database
- Create test ML model (for testing without CICIDS2017)
- Install frontend Node.js dependencies
- List available network interfaces

### 2. Install Suricata (optional but recommended)

```bash
sudo apt update && sudo apt install suricata -y
sudo systemctl start suricata
# Check logs: /var/log/suricata/eve.json
```

### 3. Install Ollama

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2
# Verify: ollama run llama3.2 "Hello"
```

### 4. Train the ML model (requires CICIDS2017 dataset)

```bash
# Download CICIDS2017 from https://www.unb.ca/cic/datasets/ids-2017.html
# Extract CSV files to /path/to/cicids2017/

cd /path/to/project
python -m ml.train --data-dir /path/to/cicids2017 --output-dir models/

# For quick testing with a small subset:
python -m ml.train --data-dir /path/to/cicids2017 --output-dir models/ --max-rows 10000
```

### 5. Configure environment

```bash
cd backend
cp .env.example .env
# Edit .env:
#   CAPTURE_INTERFACE=eth0   (run `ip a` to find your interface)
#   OLLAMA_MODEL=llama3.2
#   SURICATA_EVE_LOG=/var/log/suricata/eve.json
```

---

## Running

### Start the backend (WSL2)

```bash
cd backend
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Backend API: http://localhost:8000  
API docs: http://localhost:8000/docs

### Start the frontend (Windows terminal or WSL2)

```bash
cd frontend
npm run dev
```

Dashboard: http://localhost:5173

---

## Usage

### Upload a PCAP file for analysis

1. Open the dashboard → Live Monitoring page
2. Click "Upload PCAP"
3. Select a `.pcap` or `.pcapng` file (max 50 MB)
4. The system will: extract flows → run ML → detect threats → investigate → recommend defences

### Live monitoring

1. Ensure the backend is running with correct `CAPTURE_INTERFACE`
2. The sensor requires root/sudo in WSL2: `sudo uvicorn main:app ...`
3. The Overview page shows live threat activity

### View attack paths

1. Navigate to Attack Path Analysis
2. Select an investigation from the left panel
3. The React Flow graph shows the detected attack path

---

## API Reference

```
GET  /api/v1/dashboard/stats          Dashboard statistics
GET  /api/v1/events                   List security events (paginated)
GET  /api/v1/events/{id}              Event detail
GET  /api/v1/events/{id}/investigation Investigation result
GET  /api/v1/events/{id}/defence      Defence recommendations
POST /api/v1/flows/upload-pcap        Upload PCAP for analysis
GET  /api/v1/agents/status            All three agent statuses
GET  /api/v1/health                   System health
GET  /api/v1/reports/summary          Security report
GET  /api/v1/reports/export?format=csv Export events as CSV
WS   /ws/events                       Real-time event stream
```

Full docs available at http://localhost:8000/docs

---

## Testing

```bash
# Run all tests with coverage
./scripts/test_all.sh

# Individual test suites
cd backend
source .venv/bin/activate
pytest tests/test_suricata_service.py -v
pytest tests/test_feature_normalizer.py -v
pytest tests/test_feature_schema.py -v
pytest tests/test_risk_engine.py -v
pytest tests/test_ml_service.py -v

# Generate test model first if needed
python -m ml.create_test_model
```

---

## Known Limitations

| Limitation | Details |
|-----------|---------|
| WSL2 network visibility | WSL2 captures only WSL2 virtual interfaces, not all Windows host traffic |
| Binary ML classifier | Model classifies BENIGN/ATTACK; attack categories from rule-based logic |
| Ollama latency | LLM inference adds 5–30s per investigation; pipeline continues without it |
| SQLite scalability | Suitable for project scale; replace with PostgreSQL for production |
| Recommendation-only defence | No automatic firewall changes; all actions require admin approval |
| CICFlowMeter differences | Python extractor may differ slightly from Java reference; documented in `docs/feature_differences.md` |

---

## Troubleshooting

**Backend won't start:**
- Check `backend/.env` exists (copy from `.env.example`)
- Verify `DATABASE_URL` path is writable
- Run `pip install -r requirements.txt` in the virtual environment

**ML model not loading:**
- Run `python -m ml.create_test_model` for a test model
- Or train on CICIDS2017 with `python -m ml.train`
- Check `models/` directory exists

**Ollama not working:**
- Run `ollama list` to verify the model is installed
- Check `OLLAMA_HOST` in `.env` matches your Ollama URL
- The system degrades gracefully without Ollama

**Packet capture permission denied:**
- Run with sudo: `sudo uvicorn main:app ...`
- Or use PCAP upload instead of live capture

**WebSocket not connecting:**
- Verify backend is running on port 8000
- Check CORS_ORIGINS in `.env` includes your frontend URL

---

## Security Notice

This system is designed for authorized monitoring of networks you own or have explicit permission to monitor. It does not include offensive capabilities. All defensive recommendations require administrator manual approval before any action is taken. Do not deploy on networks without proper authorization.
