# AgentShield – System Design Document

**Version:** 1.0  
**Date:** 2026-11-01  
**Project:** AgentShield: A Multi-Agent AI Framework for Attack-Path Verification and Autonomous Cyber Defense

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                  Authorized Network Interface                │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    ┌──────▼───────┐
                    │ Packet       │
                    │ Capture      │  (Scapy / tcpdump / Npcap)
                    │ (rotating    │
                    │  PCAP)       │
                    └──────┬───────┘
                           │
           ┌───────────────┴───────────────┐
           │                               │
    ┌──────▼──────┐                ┌───────▼──────┐
    │  Suricata   │                │  CICFlowMeter │
    │  IDS/IPS    │                │  (Python)     │
    └──────┬──────┘                └───────┬───────┘
           │                               │
    EVE JSON alerts               77 Network Features
           │                               │
           └───────────────┬───────────────┘
                           │
                  ┌────────▼────────┐
                  │  Feature        │
                  │  Normalizer     │
                  └────────┬────────┘
                           │
                  ┌────────▼────────┐
                  │  Random Forest  │
                  │  Classifier     │
                  │  (BENIGN/ATTACK)│
                  └────────┬────────┘
                           │
                  ┌────────▼────────┐
                  │  Detection      │  AGENT 1
                  │  Agent          │
                  └────────┬────────┘
                           │
                  ┌────────▼────────┐
                  │  Attack         │  AGENT 2
                  │  Analysis Agent │◄── Ollama (LLM)
                  └────────┬────────┘
                           │
                  ┌────────▼────────┐
                  │  Defence        │  AGENT 3
                  │  Agent          │
                  └────────┬────────┘
                           │
                  ┌────────▼────────┐
                  │  Risk Engine    │  (deterministic)
                  └────────┬────────┘
                           │
                  ┌────────▼────────┐
                  │  SQLite DB      │
                  │  (SQLAlchemy)   │
                  └────────┬────────┘
                           │
                  ┌────────▼────────┐
                  │  FastAPI        │
                  │  (REST + WS)    │
                  └────────┬────────┘
                           │
                  ┌────────▼────────┐
                  │  React          │
                  │  SOC Dashboard  │
                  └─────────────────┘
```

---

## 2. Component Descriptions

### 2.1 Packet Capture (`capture/`)

**packet_capture.py**
- Uses `scapy` (Linux) or `pyshark`/Npcap (Windows) to write rotating PCAP files.
- Interface is configurable via `CAPTURE_INTERFACE` environment variable.
- Rotation interval configurable via `PCAP_ROTATION_SECONDS` (default: 60).
- Writes to `data/captures/live_YYYYMMDD_HHMMSS.pcap`.
- On rotation, emits an event to the processing queue.

**pcap_processor.py**
- Accepts a PCAP file path (live rotation or upload).
- Calls `flow_extractor.py` to extract 77 features per flow.
- Feeds results to the ML service.
- Returns a list of `FlowRecord` objects.

**sensor_manager.py**
- Manages the capture process lifecycle (start/stop/restart).
- Monitors capture health, reports status.
- Exposes `SensorStatus` with fields: `active`, `interface`, `packets_captured`, `last_update`.

### 2.2 Suricata Service (`services/suricata_service.py`)

- Monitors `eve.json` using tail-style file reading with position tracking.
- Parses `alert` and `flow` event types.
- Deduplicates within a 30-second window using a (src_ip, dest_ip, signature) key.
- Pushes parsed events to an asyncio queue consumed by the Detection Agent.
- Health check: verifies file exists, is recently modified, and the Suricata process is running.

**SuricataAlert schema:**
```python
class SuricataAlert(BaseModel):
    event_id: str
    timestamp: datetime
    src_ip: str
    dest_ip: str
    src_port: int
    dest_port: int
    protocol: str
    signature: str
    signature_id: int
    severity: int          # Suricata 1–3
    category: str
    action: str            # allowed / blocked
```

### 2.3 Flow Extractor (`services/flow_extractor.py`)

Produces the canonical 77-feature vector. Feature list (index-ordered, must match model training):

```
 0  Destination Port
 1  Flow Duration
 2  Total Fwd Packets
 3  Total Backward Packets
 4  Total Length of Fwd Packets
 5  Total Length of Bwd Packets
 6  Fwd Packet Length Max
 7  Fwd Packet Length Min
 8  Fwd Packet Length Mean
 9  Fwd Packet Length Std
10  Bwd Packet Length Max
11  Bwd Packet Length Min
12  Bwd Packet Length Mean
13  Bwd Packet Length Std
14  Flow Bytes/s
15  Flow Packets/s
16  Flow IAT Mean
17  Flow IAT Std
18  Flow IAT Max
19  Flow IAT Min
20  Fwd IAT Total
21  Fwd IAT Mean
22  Fwd IAT Std
23  Fwd IAT Max
24  Fwd IAT Min
25  Bwd IAT Total
26  Bwd IAT Mean
27  Bwd IAT Std
28  Bwd IAT Max
29  Bwd IAT Min
30  Fwd PSH Flags
31  Bwd PSH Flags
32  Fwd URG Flags
33  Bwd URG Flags
34  Fwd Header Length
35  Bwd Header Length
36  Fwd Packets/s
37  Bwd Packets/s
38  Min Packet Length
39  Max Packet Length
40  Packet Length Mean
41  Packet Length Std
42  Packet Length Variance
43  FIN Flag Count
44  SYN Flag Count
45  RST Flag Count
46  PSH Flag Count
47  ACK Flag Count
48  URG Flag Count
49  CWE Flag Count
50  ECE Flag Count
51  Down/Up Ratio
52  Average Packet Size
53  Avg Fwd Segment Size
54  Avg Bwd Segment Size
55  Fwd Header Length (dup)
56  Fwd Avg Bytes/Bulk
57  Fwd Avg Packets/Bulk
58  Fwd Avg Bulk Rate
59  Bwd Avg Bytes/Bulk
60  Bwd Avg Packets/Bulk
61  Bwd Avg Bulk Rate
62  Subflow Fwd Packets
63  Subflow Fwd Bytes
64  Subflow Bwd Packets
65  Subflow Bwd Bytes
66  Init_Win_bytes_forward
67  Init_Win_bytes_backward
68  act_data_pkt_fwd
69  min_seg_size_forward
70  Active Mean
71  Active Std
72  Active Max
73  Active Min
74  Idle Mean
75  Idle Std
76  Idle Max
77  Idle Min  ← index 77 (78th column, 0-based = 77)
```

Note: The list above is 0-indexed; total = 78 named features across 77 unique measurement axes (index 55 is a duplicate of index 34 matching the CICIDS2017 CSV schema).

**FlowRecord schema:**
```python
class FlowRecord(BaseModel):
    flow_id: str
    src_ip: str
    dest_ip: str
    src_port: int
    dest_port: int
    protocol: str
    timestamp: datetime
    features: List[float]   # exactly 77 values
    feature_names: List[str]
    duration_us: int
```

### 2.4 Feature Normalizer (`services/feature_normalizer.py`)

- Loads the ordered feature name list from model metadata.
- Accepts a dictionary `{feature_name: value}` and returns an ordered numpy array.
- Rejects records with missing features (logs warning, returns None).
- Replaces Inf values with a configurable cap (default: `1e9`).
- Replaces NaN with 0 (with a warning log).
- Verifies output shape matches the model's `n_features_in_`.

### 2.5 ML Service (`services/ml_service.py`)

- Loads `models/agentshield_rf.pkl` and `models/agentshield_rf_metadata.json` at startup.
- Exposes `predict(features: np.ndarray) -> PredictionResult`.
- `PredictionResult`: `label` (BENIGN/ATTACK), `confidence` (float), `probabilities` (dict).
- Caches model in memory; reloads on file change detection.
- Reports model health: loaded, feature count, version, training accuracy.

### 2.6 Ollama Service (`services/ollama_service.py`)

- Wraps Ollama REST API at `http://localhost:11434/api/generate`.
- Model name configurable via `OLLAMA_MODEL` (default: `llama3.2`).
- Timeout configurable via `OLLAMA_TIMEOUT_SECONDS` (default: 30).
- Returns structured text response.
- On connection failure: returns `None`; callers fall back to deterministic templates.
- Health check: `GET /api/tags` and verify model is available.

### 2.7 Risk Engine (`services/risk_engine.py`)

Deterministic scoring formula:

```
base_score = 0

if suricata_alert:
    base_score += severity_weight[suricata_severity]  # {1:20, 2:35, 3:50}

if ml_prediction == "ATTACK":
    base_score += ml_confidence * 30  # max 30 points

related_events = count_related_events(src_ip, last_60_min)
base_score += min(related_events * 2, 15)  # max 15 points

if known_sensitive_port(dest_port):
    base_score += 5

score = min(int(base_score), 100)
```

Severity thresholds (configurable):
- CRITICAL: 90–100
- HIGH: 70–89
- MEDIUM: 40–69
- LOW: 1–39
- NORMAL: 0

Outputs `RiskAssessment` with `score`, `severity`, `contributing_factors: List[str]`.

### 2.8 Detection Agent (`agents/detection_agent.py`)

**Processing loop:**
1. Receive events from the Suricata queue and/or the ML prediction queue.
2. Correlate: match Suricata alerts to flow records by (src_ip, dest_ip, timestamp ±5 s).
3. Apply deterministic rules to identify attack category.
4. Call `risk_engine.calculate()`.
5. Produce `DetectionEvent`.
6. Persist to `security_events` table.
7. Publish to the Attack Analysis Agent queue.
8. Broadcast via WebSocket.

**Attack category detection rules:**
```
port_scan     : SYN flag high, many distinct dest_ports, low ACK, Suricata scan sig
brute_force   : repeated auth attempts to same port (22/21/3389/445), Suricata auth sig
dos           : high flow rate, many packets same src, Suricata DoS sig
suspicious_tcp: RST storms, half-open connections
suspicious_dns: high DNS query rate, long domain names, unusual record types
botnet        : beaconing pattern (regular intervals), Suricata botnet sig
malicious     : ML=ATTACK + Suricata alert, no specific category
recon         : ICMP sweeps, low-rate port probing
```

### 2.9 Attack Analysis Agent (`agents/attack_analysis_agent.py`)

**Processing loop:**
1. Receive `DetectionEvent` from queue.
2. Query database for related events (same src_ip or dest_ip, last 24 h).
3. Build attack path graph: nodes = IPs, edges = connections with timestamps.
4. Construct evidence list from Suricata + ML + related events.
5. Call Ollama with structured prompt to generate natural-language explanation.
6. Produce `InvestigationResult`.
7. Persist to `agent_investigations` and `attack_paths` tables.

**Ollama prompt template:**
```
You are a cybersecurity analyst. Based on the following observed network evidence, 
provide a structured investigation summary. Do NOT invent CVEs or claim host 
compromise from alerts alone. Clearly distinguish observed facts from hypotheses.

Evidence:
- Source IP: {src_ip}
- Target IP: {dest_ip}
- Attack category (detected): {category}
- Suricata signatures triggered: {signatures}
- ML prediction: {ml_label} (confidence: {ml_conf:.0%})
- Related events in last 24h: {related_count}
- Ports involved: {ports}

Provide:
1. What was likely observed (2–3 sentences)
2. Possible attack progression (if evidence supports it)
3. Affected assets (based only on observed IPs/ports)
4. Recommended investigation steps
```

### 2.10 Defence Agent (`agents/defence_agent.py`)

**Processing loop:**
1. Receive `InvestigationResult` from queue.
2. Map severity + attack_type to recommendation templates.
3. Generate prioritized `RecommendedAction` list.
4. Set `requires_admin_approval = True` for all actions.
5. Set `execution_status = "RECOMMENDED"`.
6. Persist to `defence_recommendations` table.

**Recommendation templates by attack type:**
```
port_scan     → "Block {src_ip} at perimeter firewall", "Enable port-scan rate limiting"
brute_force   → "Block {src_ip}", "Review account lockout policy", "Enable MFA on {service}"
dos           → "Rate-limit {src_ip}", "Enable traffic scrubbing", "Review bandwidth limits"
botnet        → "Isolate {src_ip} from network", "Block C2 domain/IP", "Scan for malware"
suspicious_dns→ "Review DNS logs for {src_ip}", "Block suspicious domains", "Enable DNSSEC"
recon         → "Block {src_ip}", "Review exposed services", "Enable honeypot on scanned ports"
```

---

## 3. Database Schema

### Table: security_events
```sql
CREATE TABLE security_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT UNIQUE NOT NULL,
    source_ip       TEXT NOT NULL,
    destination_ip  TEXT NOT NULL,
    source_port     INTEGER,
    destination_port INTEGER,
    protocol        TEXT,
    attack_category TEXT,
    ml_prediction   TEXT,
    ml_confidence   REAL,
    suricata_alert  BOOLEAN DEFAULT FALSE,
    suricata_signature TEXT,
    risk_score      INTEGER,
    severity        TEXT,
    evidence        TEXT,      -- JSON array
    raw_suricata    TEXT,      -- JSON
    raw_flow        TEXT,      -- JSON
    status          TEXT DEFAULT 'NEW',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_se_src_ip ON security_events(source_ip);
CREATE INDEX idx_se_created ON security_events(created_at);
CREATE INDEX idx_se_severity ON security_events(severity);
```

### Table: network_flows
```sql
CREATE TABLE network_flows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id         TEXT UNIQUE NOT NULL,
    source_ip       TEXT NOT NULL,
    destination_ip  TEXT NOT NULL,
    source_port     INTEGER,
    destination_port INTEGER,
    protocol        TEXT,
    duration_us     INTEGER,
    features_json   TEXT,      -- JSON array of 77 floats
    pcap_source     TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_nf_src ON network_flows(source_ip);
CREATE INDEX idx_nf_created ON network_flows(created_at);
```

### Table: ml_predictions
```sql
CREATE TABLE ml_predictions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    prediction_id   TEXT UNIQUE NOT NULL,
    flow_id         TEXT REFERENCES network_flows(flow_id),
    label           TEXT NOT NULL,         -- BENIGN / ATTACK
    confidence      REAL NOT NULL,
    probabilities   TEXT,                  -- JSON
    model_version   TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Table: agent_investigations
```sql
CREATE TABLE agent_investigations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id    TEXT UNIQUE NOT NULL,
    event_id            TEXT REFERENCES security_events(event_id),
    attack_type         TEXT,
    entry_point         TEXT,
    target              TEXT,
    affected_assets     TEXT,   -- JSON array
    observed_evidence   TEXT,   -- JSON array
    hypotheses          TEXT,   -- JSON array
    potential_impact    TEXT,
    confidence          REAL,
    explanation         TEXT,
    llm_used            BOOLEAN DEFAULT FALSE,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Table: attack_paths
```sql
CREATE TABLE attack_paths (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    path_id         TEXT UNIQUE NOT NULL,
    investigation_id TEXT REFERENCES agent_investigations(investigation_id),
    nodes           TEXT,   -- JSON array of {id, ip, type, risk}
    edges           TEXT,   -- JSON array of {source, target, label, observed}
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Table: risk_assessments
```sql
CREATE TABLE risk_assessments (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id       TEXT UNIQUE NOT NULL,
    event_id            TEXT REFERENCES security_events(event_id),
    score               INTEGER NOT NULL,
    severity            TEXT NOT NULL,
    contributing_factors TEXT,  -- JSON array
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Table: defence_recommendations
```sql
CREATE TABLE defence_recommendations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    defence_id          TEXT UNIQUE NOT NULL,
    investigation_id    TEXT REFERENCES agent_investigations(investigation_id),
    risk_level          TEXT,
    recommended_actions TEXT,   -- JSON array of action objects
    priority            TEXT,
    requires_admin_approval BOOLEAN DEFAULT TRUE,
    execution_status    TEXT DEFAULT 'RECOMMENDED',
    admin_notes         TEXT,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Table: system_health
```sql
CREATE TABLE system_health (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    component       TEXT NOT NULL,
    status          TEXT NOT NULL,   -- OK / DEGRADED / DOWN
    details         TEXT,            -- JSON
    checked_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_sh_comp ON system_health(component, checked_at);
```

### Table: audit_logs
```sql
CREATE TABLE audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    action      TEXT NOT NULL,
    actor       TEXT DEFAULT 'system',
    details     TEXT,               -- JSON
    ip_address  TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## 4. API Design

### Base URL
`http://localhost:8000/api/v1`

### WebSocket
`ws://localhost:8000/ws/events`

### Endpoints

#### Dashboard
```
GET  /api/v1/dashboard/stats
GET  /api/v1/dashboard/threat-timeline?hours=24
GET  /api/v1/dashboard/severity-distribution
GET  /api/v1/dashboard/top-sources?limit=10
```

#### Security Events
```
GET  /api/v1/events?page=1&limit=20&severity=HIGH&from=ISO&to=ISO
GET  /api/v1/events/{event_id}
GET  /api/v1/events/{event_id}/investigation
GET  /api/v1/events/{event_id}/defence
```

#### Network Flows
```
GET  /api/v1/flows?page=1&limit=20
GET  /api/v1/flows/{flow_id}
POST /api/v1/flows/upload-pcap        (multipart, max 50 MB)
GET  /api/v1/flows/upload/{task_id}/status
```

#### Agents
```
GET  /api/v1/agents/status
GET  /api/v1/agents/detection/events?limit=20
GET  /api/v1/agents/analysis/investigations?limit=20
GET  /api/v1/agents/defence/recommendations?limit=20
POST /api/v1/agents/defence/recommendations/{id}/approve
POST /api/v1/agents/defence/recommendations/{id}/reject
```

#### Health
```
GET  /api/v1/health                   (overall)
GET  /api/v1/health/suricata
GET  /api/v1/health/model
GET  /api/v1/health/ollama
GET  /api/v1/health/capture
GET  /api/v1/health/database
```

#### Reports
```
GET  /api/v1/reports/summary?from=ISO&to=ISO
GET  /api/v1/reports/export?format=pdf|csv&from=ISO&to=ISO
```

#### Settings
```
GET  /api/v1/settings
PUT  /api/v1/settings
```

---

## 5. WebSocket Message Types

```typescript
type WSMessage =
  | { type: "new_event";        payload: SecurityEvent }
  | { type: "stats_update";     payload: DashboardStats }
  | { type: "agent_status";     payload: AgentStatus }
  | { type: "health_update";    payload: HealthStatus }
  | { type: "connection_ack";   payload: { snapshot: DashboardStats } }
  | { type: "pcap_task_update"; payload: { task_id: string; status: string; progress: number } }
```

---

## 6. Frontend Architecture

### Tech Stack
- React 18 + Vite 5
- TypeScript 5
- Tailwind CSS 3
- Recharts 2
- React Flow 11
- React Router 6
- Lucide React
- React Query (TanStack Query v5) for REST data fetching
- Custom WebSocket hook for live updates

### Directory Structure
```
frontend/
├── src/
│   ├── api/          # typed API client functions
│   ├── components/
│   │   ├── common/   # Button, Badge, Card, StatusIndicator, Table
│   │   ├── charts/   # ThreatTimeline, SeverityPie, FlowRateChart
│   │   ├── flow/     # AttackPathGraph (React Flow wrapper)
│   │   └── layout/   # Sidebar, Header, StatusBar
│   ├── hooks/        # useWebSocket, useEvents, useAgentStatus
│   ├── pages/
│   │   ├── Overview.tsx
│   │   ├── LiveMonitoring.tsx
│   │   ├── ThreatDetection.tsx
│   │   ├── AttackPath.tsx
│   │   ├── AgentActivity.tsx
│   │   ├── EventDetail.tsx
│   │   ├── Reports.tsx
│   │   └── Settings.tsx
│   ├── store/        # Zustand or React Context global state
│   ├── types/        # TypeScript interfaces matching backend schemas
│   └── utils/        # formatters, severity colors, risk helpers
├── public/
├── index.html
├── vite.config.ts
├── tailwind.config.ts
└── tsconfig.json
```

### Color System (dark cybersecurity theme)
```
Background:   #0a0e1a  (near-black navy)
Surface:      #111827  (card backgrounds)
Border:       #1f2937
Text primary: #f9fafb
Text muted:   #6b7280
CRITICAL:     #ef4444  (red-500)
HIGH:         #f97316  (orange-500)
MEDIUM:       #eab308  (yellow-500)
LOW:          #22c55e  (green-500)
NORMAL:       #3b82f6  (blue-500)
Accent:       #06b6d4  (cyan-500)
```

---

## 7. Processing Pipeline Data Flow

```
1. PacketCapture writes /data/captures/live_YYYYMMDD_HHMMSS.pcap every 60s
2. PcapProcessor.process(file) →
   a. FlowExtractor.extract(file) → List[FlowRecord(77 features)]
   b. FeatureNormalizer.normalize(flow_record) → np.ndarray
   c. MLService.predict(array) → PredictionResult
   d. Persist flow + prediction to DB
   e. If ATTACK → enqueue to detection_queue

3. SuricataService tails eve.json →
   a. Parse alert/flow events
   b. Deduplicate
   c. Persist to DB
   d. Enqueue to detection_queue

4. DetectionAgent.run():
   a. Dequeue from detection_queue
   b. Correlate ML predictions + Suricata alerts
   c. Apply category rules
   d. RiskEngine.calculate() → RiskAssessment
   e. Produce DetectionEvent
   f. Persist to security_events + risk_assessments
   g. WebSocket broadcast
   h. Enqueue to analysis_queue

5. AttackAnalysisAgent.run():
   a. Dequeue from analysis_queue
   b. DB query for related events
   c. Build attack path graph
   d. OllamaService.generate(prompt) → explanation
   e. Produce InvestigationResult
   f. Persist to agent_investigations + attack_paths
   g. WebSocket broadcast
   h. Enqueue to defence_queue

6. DefenceAgent.run():
   a. Dequeue from defence_queue
   b. Map to recommendation templates
   c. Produce DefenceRecommendation (status=RECOMMENDED)
   d. Persist to defence_recommendations
   e. WebSocket broadcast

7. FastAPI serves all persisted data via REST
8. WebSocket streams all new events to React dashboard
```

---

## 8. ML Training Pipeline

```
ml/
├── train.py              # full training script
├── evaluate.py           # evaluation with real metrics
├── data_loader.py        # CICIDS2017 CSV loader + cleaner
├── feature_selector.py   # selects the 77 features
└── README_training.md    # dataset download + training instructions

Training steps:
1. Load CICIDS2017 CSV files
2. Drop duplicates, handle infinities, drop NaN
3. Label encode: BENIGN=0, all attack types=1
4. Select 77 features (defined in services/feature_normalizer.py)
5. Time-aware train/test split (first 70% by timestamp = train)
6. Train RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
7. Evaluate on test set; log actual metrics
8. Save model to models/agentshield_rf.pkl
9. Save metadata to models/agentshield_rf_metadata.json
```

---

## 9. Environment Configuration

All config via `backend/.env`:
```ini
# Network
CAPTURE_INTERFACE=eth0
PCAP_ROTATION_SECONDS=60
PCAP_OUTPUT_DIR=data/captures

# Suricata
SURICATA_EVE_LOG=/var/log/suricata/eve.json
SURICATA_DEDUP_WINDOW_SECONDS=30

# ML
MODEL_PATH=models/agentshield_rf.pkl
MODEL_METADATA_PATH=models/agentshield_rf_metadata.json

# Ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2
OLLAMA_TIMEOUT_SECONDS=30

# Database
DATABASE_URL=sqlite:///./data/agentshield.db

# API
API_HOST=0.0.0.0
API_PORT=8000
CORS_ORIGINS=http://localhost:5173

# Upload
MAX_PCAP_UPLOAD_MB=50

# Risk thresholds
RISK_CRITICAL_THRESHOLD=90
RISK_HIGH_THRESHOLD=70
RISK_MEDIUM_THRESHOLD=40
RISK_LOW_THRESHOLD=1

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/agentshield.log
```

---

## 10. Security Considerations

1. PCAP uploads validated by magic bytes (not just extension).
2. File size enforced at API layer before writing to disk.
3. All temp PCAP uploads deleted after processing.
4. SQL queries use SQLAlchemy ORM (parameterized).
5. Admin actions (approve/reject defence recommendations) logged to audit_logs.
6. No credentials in source code; all from `.env`.
7. CORS locked to frontend origin.
8. Defence Agent never calls OS commands in recommendation-only mode.

---

## 11. Known Limitations

| Limitation | Mitigation |
|-----------|-----------|
| WSL2 cannot capture all Windows host traffic | Document clearly; capture on WSL2 interfaces only; optionally bridge via Npcap on Windows |
| Binary ML classifier cannot identify specific attack sub-types | Suricata + rule logic provides attack category; ML provides ATTACK/BENIGN signal |
| Ollama adds latency | Async processing; fallback to template explanations |
| SQLite not suitable for high-volume production | Acceptable for project scale; schema designed for PostgreSQL migration |
| 77-feature extraction accuracy vs Java CICFlowMeter | Document known differences; maintain regression tests |
